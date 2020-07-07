# AWS IAM Authenticator for Kubernetes

A tool to use AWS IAM credentials to authenticate to a Kubernetes cluster.
The initial work on this tool was driven by Heptio. The project receives contributions from multiple community engineers and is currently maintained by Heptio and Amazon EKS OSS Engineers.

## Why do I want this?
If you are an administrator running a Kubernetes cluster on AWS, you already need to manage AWS IAM credentials to provision and update the cluster.
By using AWS IAM Authenticator for Kubernetes, you avoid having to manage a separate credential for Kubernetes access.
AWS IAM also provides a number of nice properties such as an out of band audit trail (via CloudTrail) and 2FA/MFA enforcement.

If you are building a Kubernetes installer on AWS, AWS IAM Authenticator for Kubernetes can simplify your bootstrap process.
You won't need to somehow smuggle your initial admin credential securely out of your newly installed cluster.
Instead, you can create a dedicated `KubernetesAdmin` role at cluster provisioning time and set up Authenticator to allow cluster administrator logins.

## How do I use it?
Assuming you have a cluster running in AWS and you want to add AWS IAM Authenticator for Kubernetes support, you need to:
 1. Create an IAM role you'll use to identify users.
 2. Run the Authenticator server as a DaemonSet.
 3. Configure your API server to talk to Authenticator.
 4. Set up kubectl to use Authenticator tokens.

### 1. Create an IAM role
First, you must create one or more IAM roles that will be mapped to users/groups inside your Kubernetes cluster.
The easiest way to do this is to log into the AWS Console:
 - Choose the "Role for cross-account access" / "Provide access between AWS accounts you own" option.
 - Paste in your AWS account ID number (available in the top right in the console).
 - Your role does not need any additional policies attached.

This will create an IAM role with no permissions that can be assumed by authorized users/roles in your account.
Note the Amazon Resource Name (ARN) of your role, which you will need below.

You can also do this in a single step using the AWS CLI instead of the AWS Console:
```sh
# get your account ID
ACCOUNT_ID=$(aws sts get-caller-identity --output text --query 'Account')

# define a role trust policy that opens the role to users in your account (limited by IAM policy)
POLICY=$(echo -n '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::'; echo -n "$ACCOUNT_ID"; echo -n ':root"},"Action":"sts:AssumeRole","Condition":{}}]}')

# create a role named KubernetesAdmin (will print the new role's ARN)
aws iam create-role \
  --role-name KubernetesAdmin \
  --description "Kubernetes administrator role (for AWS IAM Authenticator for Kubernetes)." \
  --assume-role-policy-document "$POLICY" \
  --output text \
  --query 'Role.Arn'
```

You can also skip this step and use:
 - An existing role (such as a cross-account access role).
 - An IAM user (see `mapUsers` below).
 - An EC2 instance or a federated role (see `mapRoles` below).

### 2. Run the server
The server is meant to run on each of your master nodes as a DaemonSet with host networking so it can expose a localhost port.

For a sample ConfigMap and DaemonSet configuration, see [`deploy/example.yaml`](./deploy/example.yaml).

#### (Optional) Pre-generate a certificate, key, and kubeconfig
If you're building an automated installer, you can also pre-generate the certificate, key, and webhook kubeconfig files easily using `aws-iam-authenticator init`.
This command will generate files and place them in the configured output directories.

You can run this on each master node prior to starting the API server.
You could also generate them before provisioning master nodes and install them in the appropriate host paths.

If you do not pre-generate files, `aws-iam-authenticator server` will generate them on demand.
This works but requires that you restart your Kubernetes API server after installation.

### 3. Configure your API server to talk to the server
The Kubernetes API integrates with AWS IAM Authenticator for Kubernetes using a [token authentication webhook](https://kubernetes.io/docs/admin/authentication/#webhook-token-authentication).
When you run `aws-iam-authenticator server`, it will generate a webhook configuration file and save it onto the host filesystem.
You'll need to add a single additional flag to your API server configuration:
```
--authentication-token-webhook-config-file=/etc/kubernetes/aws-iam-authenticator/kubeconfig.yaml
```

On many clusters, the API server runs as a static pod.
You can add the flag to `/etc/kubernetes/manifests/kube-apiserver.yaml`.
Make sure the host directory `/etc/kubernetes/aws-iam-authenticator/` is mounted into your API server pod.
You may also need to restart the kubelet daemon on your master node to pick up the updated static pod definition:
```
systemctl restart kubelet.service
```

### 4. Create IAM role/user to kubernetes user/group mappings
The default behavior of the server is to source mappings exclusively from the
`mapUsers` and `mapRoles` fields of its configuration file. See [Full
Configuration Format](#full-configuration-format) below for details.

Using the `--backend-mode` flag, you can configure the server to source
mappings from two additional backends: an EKS-style ConfigMap
(`--backend-mode=EKSConfigMap`) or `IAMIdentityMapping` custom resources
(`--backend-mode=CRD`). The default backend, the server configuration file
that's mounted by the server pod, corresponds to `--backend-mode=MountedFile`.

You can pass a comma-separated list of these backends to have the server search
them in order. For example, with `--backend-mode=EKSConfigMap,MountedFile`, the
server will search the EKS-style ConfigMap for mappings then, if it doesn't
find a mapping for the given IAM role/user, the server configuration file. If a
mapping for the same IAM role/user exists in multiple backends, the server will
use the mapping in the backend that occurs first in the comma-separated list.
In this example, if a mapping is found in the EKS ConfigMap then it will be
used whether or not a duplicate or conflicting mapping exists in the server
configuration file.

Note that when setting a single backend, the server will *only* source from
that one and ignore the others even if they exist. For example, with
`--backend-mode=CRD`, the server will *only* source from `IAMIdentityMappings`
and ignore the mounted file and EKS ConfigMap.

#### `MountedFile`
This is the default backend of mappings and sufficient for most users. See
[Full Configuration Format](#full-configuration-format) below for details.

#### `CRD` (alpha)
This backend models each IAM mapping as an `IAMIdentityMapping` [Kubernetes
Custom
Resource](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/).
This approach enables you to maintain mappings in a Kubernetes-native way using
kubectl or the API. Plus, syntax errors (like misaligned YAML) can be more
easily caught and won't affect all mappings.

To setup an `IAMIdentityMapping` CRD you'll first need to `apply` the CRD
manifest:

```
kubectl apply -f deploy/iamidentitymapping.yaml
```

With the CRDs deployed you can then create Custom Resources which model your
IAM Identities. See
[`./deploy/example-iamidentitymapping.yaml`](deploy/example-iamidentitymapping.yaml):

```
---
apiVersion: iamauthenticator.k8s.aws/v1alpha1
kind: IAMIdentityMapping
metadata:
  name: kubernetes-admin
spec:
  # Arn of the User or Role to be allowed to authenticate
  arn: arn:aws:iam::XXXXXXXXXXXX:user/KubernetesAdmin
  # Username that Kubernetes will see the user as, this is useful for setting
  # up allowed specific permissions for different users
  username: kubernetes-admin
  # Groups to be attached to your users/roles. For example `system:masters` to
  # create cluster admin, or `system:nodes`, `system:bootstrappers` for nodes to
  # access the API server.
  groups:
  - system:masters
```

#### `EKSConfigMap`
The EKS-style `kube-system/aws-auth` ConfigMap serves as the backend. The
ConfigMap is expected to be in exactly the same format as in EKS clusters:
https://docs.aws.amazon.com/eks/latest/userguide/add-user-role.html. This is
useful if you're migrating from/to EKS and want to keep your mappings, or are
running EKS in addition to some other AWS cluster(s) and want to have the same
mappings in each.

### 5. Set up kubectl to use authentication tokens provided by AWS IAM Authenticator for Kubernetes

> This requires a 1.10+ `kubectl` binary to work. If you receive `Please enter Username:` when trying to use `kubectl` you need to update to the latest `kubectl`

Finally, once the server is set up you'll want to authenticate.
You will still need a `kubeconfig` that has the public data about your cluster (cluster CA certificate, endpoint address).
The `users` section of your configuration, however, should include an exec section ([refer to the v1.10 docs](https://kubernetes.io/docs/admin/authentication/#client-go-credential-plugins))::
```yaml
# [...]
users:
- name: kubernetes-admin
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1alpha1
      command: aws-iam-authenticator
      args:
        - "token"
        - "-i"
        - "REPLACE_ME_WITH_YOUR_CLUSTER_ID"
        - "-r"
        - "REPLACE_ME_WITH_YOUR_ROLE_ARN"
  # no client certificate/key needed here!
```

This means the `kubeconfig` is entirely public data and can be shared across all Authenticator users.
It may make sense to upload it to a trusted public location such as AWS S3.

Make sure you have the `aws-iam-authenticator` binary installed.
You can install it with `go get -u -v sigs.k8s.io/aws-iam-authenticator/cmd/aws-iam-authenticator`.

To authenticate, run `kubectl --kubeconfig /path/to/kubeconfig" [...]`.
kubectl will `exec` the `aws-iam-authenticator` binary with the supplied params in your kubeconfig which will generate a token and pass it to the apiserver.
The token is valid for 15 minutes (the shortest value AWS permits) and can be reused multiple times.

You can also specify session name when generating the token by including `--session-name or -s` parameter. This parameter cannot be used along with `--forward-session-name`.

You can also omit `-r ROLE_ARN` to sign the token with your existing credentials without assuming a dedicated role.
This is useful if you want to authenticate as an IAM user directly or if you want to authenticate using an EC2 instance role or a federated role.

## Kops Usage
Clusters managed by [Kops](https://github.com/kubernetes/kops) can be configured to use Authenticator. For usage instructions see the [Kops documentation](https://github.com/kubernetes/kops/blob/master/docs/authentication.md#aws-iam-authenticator).

## How does it work?
It works using the AWS [`sts:GetCallerIdentity`](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html) API endpoint.
This endpoint returns information about whatever AWS IAM credentials you use to connect to it.

#### Client side (`aws-iam-authenticator token`)
We use this API in a somewhat unusual way by having the Authenticator client generate and pre-sign a request to the endpoint.
We serialize that request into a token that can pass through the Kubernetes authentication system.

#### Server side (`aws-iam-authenticator server`)
The token is passed through the Kubernetes API server and into the Authenticator server's `/authenticate` endpoint via a webhook configuration.
The Authenticator server validates all the parameters of the pre-signed request to make sure nothing looks funny.
It then submits the request to the real `https://sts.amazonaws.com` server, which validates the client's HMAC signature and returns information about the user.
Now that the server knows the AWS identity of the client, it translates this identity into a Kubernetes user and groups via a simple static mapping.

This mechanism is borrowed with a few changes from [Vault](https://www.vaultproject.io/docs/auth/aws.html#iam-auth-method).

## What is a cluster ID?
The Authenticator cluster ID is a unique-per-cluster identifier that prevents certain replay attacks.
Specifically, it prevents one Authenticator server (e.g., in a dev environment) from using a client's token to authenticate to another Authenticator server in another cluster.

The cluster ID does need to be unique per-cluster, but it doesn't need to be a secret.
Some good choices are:
 - A random ID such as from `openssl rand 16 -hex`
 - The domain name of your Kubernetes API server

The [Vault documentation](https://www.vaultproject.io/docs/auth/aws.html#iam-auth-method) also explains this attack (see `X-Vault-AWS-IAM-Server-ID`).

## Specifying Credentials & Using AWS Profiles
Credentials can be specified for use with `aws-iam-authenticator` via any of the methods available to the
[AWS SDK for Go](https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html#specifying-credentials).
This includes specifying AWS credentials with enviroment variables or by utilizing a credentials file.

AWS [named profiles](https://docs.aws.amazon.com/cli/latest/userguide/cli-multiple-profiles.html) are supported by `aws-iam-authenticator`
via the `AWS_PROFILE` environment variable. For example, to authenticate with credentials specified in the _dev_ profile the `AWS_PROFILE` can
be exported or specified explictly (e.g., `AWS_PROFILE=dev kubectl get all`). If no `AWS_PROFILE` is set, the _default_ profile is used.

The `AWS_PROFILE` can also be specified directly in the kubeconfig file
[as part of the `exec` flow](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#configuration). For example, to specify
that credentials from the _dev_ named profile should always be used by `aws-iam-authenticator`, your kubeconfig would include an `env`
key thats sets the profile:

```yaml
apiVersion: v1
clusters:
- cluster:
    server: ${server}
    certificate-authority-data: ${cert}
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: aws
  name: aws
current-context: aws
kind: Config
preferences: {}
users:
- name: aws
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1alpha1
      command: aws-iam-authenticator
      env:
      - name: "AWS_PROFILE"
        value: "dev"
      args:
        - "token"
        - "-i"
        - "mycluster"
```

This method allows the appropriate profile to be used implicitly. Note that any environment variables set as part of the `exec` flow will
take precedence over what's already set in your environment.

#### Note for federated users:
Federated AWS users often will have a "meaningful" attribute mapped onto their assumed role, such as an email address, through the account's AWS configuration.
These assumed sessions have [a few parts](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html#principaltable), the `role id`
and `caller-specified-role-name`. By default, when a federated user uses the `--role` option of `aws-iam-authenticator` to assume a new role the
`caller-specified-role-name` will be converted to a random token and the `role id` carries through to the newly assumed role.

Using `aws-iam-authenticator token ... --forward-session-name` will map the original `caller-specified-role-name` attribute onto the new STS assumed session.
This can be helpful for quickly attempting to associate "who performed action X on the K8 cluster".

Please note, **this should not be considered definitive** and needs to be cross referenced via the `role id` (which remains consistent) with CloudTrail logs
as a user could potentially change this on the client side.

## API Authorization from Outside a Cluster

It is possible to make requests to the Kubernetes API from a client that is outside the cluster, be that using the
bare Kubernetes REST API or from one of the language specific Kubernetes clients
(e.g., [Python](https://github.com/kubernetes-client/python)). In order to do so, you must create a bearer token that
is included with the request to the API. This bearer token requires you append the string `k8s-aws-v1.` with a
base64 encoded string of a signed HTTP request to the STS GetCallerIdentity Query API. This is then sent it in the
`Authorization`  header of the request.  Something to note though is that the IAM Authenticator explicitly omits
base64 padding to avoid any `=` characters thus guaranteeing a string safe to use in URLs. Below is an example in
Python on how this token would be constructed:

```python
import base64
import boto3
import re
from botocore.signers import RequestSigner

def get_bearer_token(cluster_id, region):
    STS_TOKEN_EXPIRES_IN = 60
    session = boto3.session.Session()

    client = session.client('sts', region_name=region)
    service_id = client.meta.service_model.service_id

    signer = RequestSigner(
        service_id,
        region,
        'sts',
        'v4',
        session.get_credentials(),
        session.events
    )

    params = {
        'method': 'GET',
        'url': 'https://sts.{}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15'.format(region),
        'body': {},
        'headers': {
            'x-k8s-aws-id': cluster_id
        },
        'context': {}
    }

    signed_url = signer.generate_presigned_url(
        params,
        region_name=region,
        expires_in=STS_TOKEN_EXPIRES_IN,
        operation_name=''
    )

    base64_url = base64.urlsafe_b64encode(signed_url.encode('utf-8')).decode('utf-8')

    # remove any base64 encoding padding:
    return 'k8s-aws-v1.' + re.sub(r'=*', '', base64_url)

# If making a HTTP request you would create the authorization headers as follows:

headers = {'Authorization': 'Bearer ' + get_bearer_token('my_cluster', 'us-east-1')}

```


## Troubleshooting

If your client fails with an error like `could not get token: AccessDenied [...]`, you can try assuming the role with the AWS CLI directly:

```sh
# AWS CLI version of `aws-iam-authenticator token -r arn:aws:iam::ACCOUNT:role/ROLE`:
$ aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/ROLE --role-session-name test
```

If that fails, there are a few possible problems to check for:

 - Make sure your base AWS credentials are available in your shell (`aws sts get-caller-identity` can help troubleshoot this).

 - Make sure the target role allows your source account access (in the role trust policy).

 - Make sure your source principal (user/role/group) has an IAM policy that allows `sts:AssumeRole` for the target role.

 - Make sure you don't have any explicit deny policies attached to your user, group, or in AWS Organizations that would prevent the `sts:AssumeRole`.

 - Try simulating the `sts:AssumeRole` call in the [Policy Simulator](https://policysim.aws.amazon.com/home/index.jsp).

## Full Configuration Format
The client and server have the same configuration format.
They can share the same exact configuration file, since there are no secrets stored in the configuration.

```yaml
# a unique-per-cluster identifier to prevent replay attacks (see above)
clusterID: my-dev-cluster.example.com

# default IAM role to assume for `aws-iam-authenticator token`
defaultRole: arn:aws:iam::000000000000:role/KubernetesAdmin

# server listener configuration
server:
  # localhost port where the server will serve the /authenticate endpoint
  port: 21362 # (default)

  # state directory for generated TLS certificate and private keys
  stateDir: /var/aws-iam-authenticator # (default)

  # output `path` where a generated webhook kubeconfig will be stored.
  generateKubeconfig: /etc/kubernetes/aws-iam-authenticator.kubeconfig # (default)

  # role to assume before querying EC2 API in order to discover metadata like EC2 private DNS Name
  ec2DescribeInstancesRoleARN: arn:aws:iam::000000000000:role/DescribeInstancesRole

  # AWS Account IDs to scrub from server logs. (Defaults to empty list)
  scrubbedAccounts:
  - "111122223333"
  - "222233334444"

  # each mapRoles entry maps an IAM role to a username and set of groups
  # Each username and group can optionally contain template parameters:
  #  1) "{{AccountID}}" is the 12 digit AWS ID.
  #  2) "{{SessionName}}" is the role session name, with `@` characters
  #     transliterated to `-` characters.
  #  3) "{{SessionNameRaw}}" is the role session name, without character
  #     transliteration (available in version >= 0.5).
  mapRoles:
  # statically map arn:aws:iam::000000000000:role/KubernetesAdmin to cluster admin
  - roleARN: arn:aws:iam::000000000000:role/KubernetesAdmin
    username: kubernetes-admin
    groups:
    - system:masters

  # map EC2 instances in my "KubernetesNode" role to users like
  # "aws:000000000000:instance:i-0123456789abcdef0". Only use this if you
  # trust that the role can only be assumed by EC2 instances. If an IAM user
  # can assume this role directly (with sts:AssumeRole) they can control
  # SessionName.
  - roleARN: arn:aws:iam::000000000000:role/KubernetesNode
    username: aws:{{AccountID}}:instance:{{SessionName}}
    groups:
    - system:bootstrappers
    - aws:instances

  # map nodes that should conform to the username "system:node:<private-DNS>".  This
  # requires the authenticator to query the EC2 API in order to discover the private
  # DNS of the EC2 instance originating the authentication request.  Optionally, you
  # may specify a role that should be assumed before querying the EC2 API with the
  # key "server.ec2DescribeInstancesRoleARN" (see above).
  - roleARN: arn:aws:iam::000000000000:role/KubernetesNode
    username: system:node:{{EC2PrivateDNSName}}
    groups:
    - system:nodes
    - system:bootstrappers

  # map federated users in my "KubernetesAdmin" role to users like
  # "admin:alice-example.com". The SessionName is an arbitrary role name
  # like an e-mail address passed by the identity provider. Note that if this
  # role is assumed directly by an IAM User (not via federation), the user
  # can control the SessionName.
  - roleARN: arn:aws:iam::000000000000:role/KubernetesAdmin
    username: admin:{{SessionName}}
    groups:
    - system:masters

  # map federated users in my "KubernetesOtherAdmin" role to users like
  # "alice-example.com". The SessionName is an arbitrary role name
  # like an e-mail address passed by the identity provider. Note that if this
  # role is assumed directly by an IAM User (not via federation), the user
  # can control the SessionName.  Note that the "{{SessionName}}" macro is
  # quoted to ensure it is properly parsed as a string.
  - roleARN: arn:aws:iam::000000000000:role/KubernetesOtherAdmin
    username: "{{SessionName}}"
    groups:
    - system:masters

  # each mapUsers entry maps an IAM role to a static username and set of groups
  mapUsers:
  # map user IAM user Alice in 000000000000 to user "alice" in group "system:masters"
  - userARN: arn:aws:iam::000000000000:user/Alice
    username: alice
    groups:
    - system:masters

  # automatically map IAM ARN from these accounts to username.
  # NOTE: Always use quotes to avoid the account numbers being recognized as numbers
  # instead of strings by the yaml parser.
  mapAccounts:
  - "012345678901"
  - "456789012345"

  # source mappings from this file (mapUsers, mapRoles, & mapAccounts)
  backendMode:
  - MountedFile
```

## Community, discussion, contribution, and support

Learn how to engage with the Kubernetes community on the [community page](http://kubernetes.io/community/).

You can reach the maintainers of this project at:

- [Slack](https://kubernetes.slack.com/messages/sig-aws)
- [Mailing List](https://groups.google.com/forum/#!forum/kubernetes-sig-aws)

### Code of conduct

Participation in the Kubernetes community is governed by the [Kubernetes Code of Conduct](code-of-conduct.md).
