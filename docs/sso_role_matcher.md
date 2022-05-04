# SSO Role Matcher

Maps configuration for an AWS SSO managed IAM Role to a Kubernetes username and groups.

## Feature state

Alpha

## Use case

Easy and robust configuration for AWS SSO managed roles, which currently have two main issues:

- Confusing configuration. To use an SSO role, a user needs to map the Role ARN of the SSO ROle, minus the path.

For example: given a permission set `MyPermissionSet`, region `us-east-1` and account number `000000000000`; AWS SSO
creates a role: `arn:aws:iam::000000000000:role/aws-reserved/sso.amazonaws.com/us-east-1/AWSReservedSSO_MyPermissionSet_1234567890abcde`.

To match this role, a user would need to create a mapRoles entry like:
```
  mapRoles: |
  - rolearn: arn:aws:iam::000000000000:role/AWSReservedSSO_MyPermissionSet_1234567890abcde
    username: ...
    groups: ...
```

- Brittle configuration. If AWS SSO recreates IAM Roles, they receive a different random suffix and all the users of that
role can no longer authenticate.

## New UX

Users can create a mapRoles entry that will automatically match roles created by AWS SSO without needing to be updated
every time the roles are changed.

Users will now create mapRoles entries like:
```
  mapRoles: |
  - sso:
      permissionSetName: MyPermissionSet
      accountID: "000000000000"
    username: ...
    groups: ...
```

If the user is using the aws-us-govt or aws-cn partitions, they must specify the partition attribute in the `sso` structure.

## Implementation

config.RoleMapping will be extended with a nested structure containing the necessary information to construct a canonicalized
Role Arn. The random suffix will not need to be specified and will instead be matched for the user by constructing the
expect ARN and applying a wildcard to the end.

Users are protected from non-AWS SSO created roles as the AWS API prevents roles being manually created with AWSReservedSSO
at the beginning of their names.
