# kubernetes-aws-authenticator

A tool for using AWS IAM credentials to authenticate to a Kubernetes cluster.

**Warning: this is a proof of concept and probably doesn't belong in your production clusters yet.Talk to [@mattmoyer](https://github.com/mattmoyer) if you're interested in it.**

## Why do I want this?
If you are an administrator running a Kubernetes cluster on AWS, you already need to manage AWS credentials for provisioning and updating the cluster.
By using kubernetes-aws-authenticator, you avoid having to manage a separate credential for Kubernetes access.
AWS IAM also provides a number of nice properties such as an out of band audit trail (via CloudTrail) and 2FA/MFA enforcement.

If you are building a Kubernetes installer on AWS, kubernetes-aws-authenticator can simplify your bootstrap process.
You won't need to somehow smuggle your initial admin credential securely out of your newly installed cluster.
Instead, you can create a dedicated `KubernetesAdmin` role at cluster provisioning time and set up kubernetes-aws-authenticator to allow cluster administrator logins.

## How do I use it?
Assuming you have a cluster running in AWS and you want to add kubernetes-aws-authenticator support, you need to:
 1. Create an IAM role you'll use to identify users.
 2. Run the kubernetes-aws-authenticator server as a DaemonSet.
 3. Configure your API server to talk to kubernetes-aws-authenticator.
 4. Set up kubectl to use kubernetes-aws-authenticator tokens.

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
  --description "Kubernetes administrator role (for kubernetes-aws-authenticator)." \
  --assume-role-policy-document "$POLICY" \
  --output text \
  --query 'Role.Arn'
```

You can also skip this step and use:
 - An existing role (such as a cross-account access role).
 - An IAM user (see `mapUsers` below).
 - An EC2 instance role (see `mapEC2InstanceRoles` below).

### 2. Run the server
The server is meant to run on each of your master nodes as a DaemonSet with host networking so it can expose a localhost port.

For a sample ConfigMap and DaemonSet configuration, see [`example.yaml`](./example.yaml).

Also note that you must generate and copy all the files required by the server to master nodes, or otherwise any pod in the daemonset will fail to start.

Fortunately, kubernetes-aws-authenticator has a convenient command to generate the files for you.
Run the `init` command:

```
$ ./kubernetes-aws-authenticator -c config.yaml init
INFO[2017-10-17T16:39:42+09:00] generated a new private key and certificate   certBytes=819 keyBytes=1192
INFO[2017-10-17T16:39:42+09:00] saving new key and certificate                certPath=cert.pem keyPath=key.pem
INFO[2017-10-17T16:39:42+09:00] loaded existing keypair                       certPath=cert.pem keyPath=key.pem
INFO[2017-10-17T16:39:42+09:00] writing webhook kubeconfig file               kubeconfigPath=kubernetes-aws-authenticator.kubeconfig
INFO[2017-10-17T16:39:42+09:00] copy cert.pem to /var/kubernetes-aws-authenticator/cert.pem on kubernetes master node(s)
INFO[2017-10-17T16:39:42+09:00] copy key.pem to /var/kubernetes-aws-authenticator/key.pem on kubernetes master node(s)
INFO[2017-10-17T16:39:42+09:00] copy kubernetes-aws-authenticator.kubeconfig to /etc/kubernetes/kubernetes-aws-authenticator.kubeconfig on kubernetes master node(s)
INFO[2017-10-17T16:39:42+09:00] configure your apiserver with `--authentication-token-webhook-config-file=/etc/kubernetes/kubernetes-aws-authenticator.kubeconfig` to enable authentication with kubernetes-aws-authenticator
```

Then, you should upload mentioned files accordingly by utilizing your node/cluster provisioning tool or manually.

### 3. Configure your API server to talk to the server
The Kubernetes API integrates with kubernetes-aws-authenticator using a [token authentication webhook](https://kubernetes.io/docs/admin/authentication/#webhook-token-authentication).
When you run `kubernetes-aws-authenticator server`, it will generate a webhook configuration file and save it onto the host filesystem.
You'll need to add a single additional flag to your API server configuration:
```
--authentication-token-webhook-config-file=/etc/kubernetes/kubernetes-aws-authenticator.kubeconfig
```

On many clusters, the API server runs as a static pod.
You can add the flag to `/etc/kubernetes/manifests/kube-apiserver.yaml`.
You may also need to restart the kubelet daemon on your master node to pick up the updated static pod definition:
```
systemctl restart kubelet.service
```

### 4. Set up kubectl to use kubernetes-aws-authenticator tokens
Finally, once the server is set up you'll want to authenticate!
You will still need a `kubeconfig` that has the public data about your cluster (cluster CA certificate, endpoint address).
The `users` section of your configuration, however, can be mostly blank:
```yaml
# [...]
users:
- name: kubernetes-admin
  # no client certificate/key needed here!
```

This means the `kubeconfig` is entirely public data and can be shared across all kubernetes-aws-authenticator users.
It may make sense to upload it to a trusted public location such as AWS S3.

Make sure you have the `kubernetes-aws-authenticator` binary installed.
You can install it with `go get -u -v github.com/heptiolabs/kubernetes-aws-authenticator`.

To authenticate, run `kubectl --kubeconfig /path/to/kubeconfig --token "$(kubernetes-aws-authenticator token -i CLUSTER_ID -r ROLE_ARN)" [...]`.
You can simplify this with an alias or shell wrapper.
The token is valid for 15 minutes (the shortest value AWS permits) and can be reused multiple times.

You can also omit `-r ROLE_ARN` to sign the token with your existing credentials without assuming a dedicated role.
This is useful if you want to authenticate as an IAM user directly or if you want to authenticate using an EC2 instance role.

## How does it work?
It works using the AWS [`sts:GetCallerIdentity`](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html) API endpoint.
This endpoint returns information about whatever AWS IAM credentials you use to connect to it.

#### Client side (`kubernetes-aws-authenticator token`)
We use this API in a somewhat unusual way by having the kubernetes-aws-authenticator client generate and pre-sign a request to the endpoint.
We serialize that request into a token that can pass through the Kubernetes authentication system.

#### Server side (`kubernetes-aws-authenticator server`)
The token is passed through the Kubernetes API server and into the kubernetes-aws-authenticator server's `/authenticate` endpoint via a webhook configuration.
The kubernetes-aws-authenticator server validates all the parameters of the pre-signed request to make sure nothing looks funny.
It then submits the request to the real `https://sts.amazonaws.com` server, which validates the client's HMAC signature and returns information about the user.
Now that the server knows the AWS identity of the client, it translates this identity into a Kubernetes user and groups via a simple static mapping.

This mechanism is borrowed with a few changes from [Vault](https://www.vaultproject.io/docs/auth/aws.html#iam-authentication-method).

## What is a cluster ID?
The kubernetes-aws-authenticator cluster ID is a unique-per-cluster identifier that prevents certain replay attacks.
Specifically, it prevents one kubernetes-aws-authenticator server (e.g., in a dev environment) from using a client's token to authenticate to another kubernetes-aws-authenticator server in another cluster.

The cluster ID does need to be unique per-cluster, but it doesn't need to be a secret.
Some good choices are:
 - A random ID such as from `openssl rand 16 -hex`
 - The domain name of your Kubernetes API server

The [Vault documentation](https://www.vaultproject.io/docs/auth/aws.html#iam-authentication-method) also explains this attack (see `X-Vault-AWS-IAM-Server-ID`).

## Building


## Full Configuration Format
The client and server have the same configuration format.
They can share the same exact configuration file, since there are no secrets stored in the configuration.

```yaml
# a unique-per-cluster identifier to prevent replay attacks (see above)
clusterID: my-dev-cluster.example.com

# default IAM role to assume for `kubernetes-aws-authenticator token`
defaultRole: arn:aws:iam::000000000000:role/KubernetesAdmin

# server listener configuration
server:
  # localhost port where the server will serve the /authenticate endpoint
  port: 21362 # (default)

  # state directory for generated TLS certificate and private keys
  stateDir: /var/kubernetes-aws-authenticator # (default)

  # output `path` where a generated webhook kubeconfig will be stored.
  generateKubeconfig: /etc/kubernetes/kubernetes-aws-authenticator.kubeconfig # (default)

  # each mapRoles entry maps an IAM role to a static username and set of groups
  mapRoles:
  # e.g., map arn:aws:iam::000000000000:role/KubernetesAdmin to a cluster admin
  - roleARN: arn:aws:iam::000000000000:role/KubernetesAdmin
    username: kubernetes-admin
    groups:
    - system:masters

  # mapEC2InstanceRoles is like mapRoles but specifically for EC2 instance
  # roles. Only use this if you trust that the role can only be assumed by
  # EC2 (otherwise, you can't trust the EC2 instance ID that comes from the
  # session name). It has the benefit of letting you include the EC2
  # instance ID (e.g., "i-0123456789abcdef0") in the generated username.
  mapEC2InstanceRoles:
  # e.g., map EC2 instances in my "KubernetesNode" role to users like
  # "aws:000000000000:instance:i-0123456789abcdef0" in the groups
  - roleARN: arn:aws:iam::000000000000:role/KubernetesNode
    usernameFormat: aws:{{AccountID}}:instance:{{InstanceID}}
    groups:
    - system:bootstrappers
    - aws:instances

  # each mapUsers entry maps an IAM role to a static username and set of groups
  mapUsers:
  # e.g., map user IAM user Alice in 000000000000 to user "alice" in
  # group "system:masters"
  - userARN: arn:aws:iam::000000000000:user/Alice
    username: alice
    groups:
    - system:masters
```