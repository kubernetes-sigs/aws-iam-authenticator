# AWS IAM Authenticator Release Process

## Choosing the release version and branch

Using semantic versioning, pick a release number that makes sense by bumping the major, minor or patch release version.  If its a major or minor release (backwards incompatible changes, and new features, respectively) then you will want to start this process with an alpha release first.  Here are some examples:

Bumping a minor version after releasing a new feature:
```
v1.4.5 -> v1.5.0-alpha.0
```

After testing and allowing some time for feedback on the alpha, releasing v1.5.0:
```
v1.4.5 -> v1.5.0
```

New patch release:
```
v1.5.3 -> v1.5.4
```

New major version release with two alpha releases:
```
v1.6.2 -> v2.0.0-alpha.0
       -> v2.0.0-alpha.1
       -> v2.0.0
```

You also might need to create a release branch, if it doesn't already exist, if this release requires backporting changes to an older major or minor version.  For example, in the case that we are backporting a fix to the v0.5 release branch, and we have a v0.6 release branch, then we would do the following:

1. Create the release branch (named release-0.5) if it doesn't exist from the last v0.5.x tagged release (or check it out if it already exists).
2. Cherry-pick the necessary commits onto the release branch.
3. Follow the instructions below to create the release commit.
4. Create a pull request to merge your fork of the release branch into the upstream release branch (i.e. nckturner/aws-iam-authenticator/release-0.5 -> kubernetes-sigs/aws-iam-authenticator/release-0.5).
5. CI will handle the rest automatically. This includes:
   - creating and pushing the git tag into the upstream release branch
   - running Goreleaser on the release branch
   - creating the GitHub release
   - Populating the release with the changes
   - building and uploading the binaries to the release

## Creating the release commit

Update the `version.txt` with your new semantic version. This must be a standalone commit which only updates the `version.txt` file.

Also, bump the image version in `deploy/example.yaml` to the new version.

Push (or cherry-pick) the changes to a branch on your fork, and create a PR against the kubernetes-sigs upstream repository.

## Check the release on GitHub

Look at the release that was just published and validate that the release has the appropriate assets.  The assets should include the following:

```
authenticator_0.6.26_checksums.txt
aws-iam-authenticator_0.6.26_darwin_amd64
aws-iam-authenticator_0.6.26_darwin_arm64
aws-iam-authenticator_0.6.26_linux_amd64
aws-iam-authenticator_0.6.26_linux_arm64
aws-iam-authenticator_0.6.26_linux_ppc64le
aws-iam-authenticator_0.6.26_linux_s390x
aws-iam-authenticator_0.6.26_windows_amd64.exe
Source code (zip)
Source code (tar.gz)
```

## Post Release

In a new PR after the images are pushed to ECR, update the yaml in `deploy/example.yaml`:

```
        image: 602401143452.dkr.ecr.us-west-2.amazonaws.com/amazon/aws-iam-authenticator:v0.5.2
```
