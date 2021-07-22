# AWS IAM Authenticator Release Process

NOTE: Your GitHub account must have the required permissions and you must have generated a GitHub token.

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

You also might need to create a release branch, if it doesn't already exist, if this release requires backporting changes to an older major or minor version.  For example, in the case that we are backporting a fix to the v0.5 release branch, and we have a v0.6 release branch (which we don't at the time of writing), then we would do the following: 

1. Create the release branch (named release-0.5) if it doesn't exist from the last v0.5.x tagged release (or check it out if it already exists).
2. Cherry-pick the necessary commits onto the release branch.
3. Follow the instructions below to create the release commit.
4. Create a pull request to merge your fork of the release branch into the upstream release branch (i.e. nckturner/aws-iam-authenticator/release-0.5 -> kubernetes-sigs/aws-iam-authenticator/release-0.5).
5. Follow the instructions below, except creating the tag on the release branch instead of master.
6. Run goreleaser from the release branch.

## Creating the release commit

We need to generate the CHANGELOG for the new release by running `./hack/changelog.py`.  First check the correctness of the output using the `--print-only` flag.  Pass the previous release tag, and the commit SHA of the most recent commit (the new tag will include the changelog, so it hasn't been created yet).

```
./hack/changelog.py --token=$GITHUB_TOKEN --section-title="Release v0.5.2" --range=v0.5.1..90653708db3f6437a446bbeec15b5036db66a855 --print-only
```

After checking for correctness, pass the `--changelog-file` argument to add the new text.
```
./hack/changelog.py --token=$GITHUB_TOKEN --section-title="Release v0.5.2" --range=v0.5.1..90653708db3f6437a446bbeec15b5036db66a855 --changelog-file=CHANGELOG.md
```

Also, bump the image version in `deploy/example.yaml` to the new version.

Push the changes to a branch on your fork, and create a PR against the kubernetes-sigs upstream repository.


## Tagging the release

One the PR merges, pull the master branch locally and tag the release commit with the relase tag.
```
git pull upstream master
git tag v0.5.2
```

## Run goreleaser

In order to run goreleaser to make the release, you'll need to authenticate to the release ECR registry, and then run goreleaser.

```
aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin 602401143452.dkr.ecr.us-west-2.amazonaws.com
goreleaser release --rm-dist
```

TODO: configure goreleaser to use `./hack/changelog.py` to format the release text.

## Check the release on GitHub

Look at the release that was just published and validate that the release has the appropriate assets.  The assets should include the following:

```
authenticator_0.5.2_checksums.txt
aws-iam-authenticator-0.5.2.tar.gz
aws-iam-authenticator-0.5.2.zip
aws-iam-authenticator_0.5.2_darwin_amd64
aws-iam-authenticator_0.5.2_linux_amd64
aws-iam-authenticator_0.5.2_windows_amd64.exe
Source code (zip)
Source code (tar.gz)
```

Check the ECR registry to make sure that the images were published.  Finally, edit the release text to match previous releases, by copying the changelog text and adding the container image links. The format of the release text should be similar to the following:

````
## Changelog

* Added partition flag ([#341](https://github.com/kubernetes-sigs/aws-iam-authenticator/pull/341), @micahhausler)
* Update link to Kops docs site ([#338](https://github.com/kubernetes-sigs/aws-iam-authenticator/pull/338), @rifelpet)
* Security Improvements on the example yaml ([#335](https://github.com/kubernetes-sigs/aws-iam-authenticator/pull/335), @pjbgf)
* Fix RBAC on example file: service account requires get to ConfigMap ([#334](https://github.com/kubernetes-sigs/aws-iam-authenticator/pull/334), @pjbgf)
* Add AccessKeyID as variable for username ([#337](https://github.com/kubernetes-sigs/aws-iam-authenticator/pull/337), @pjbgf)
* Added server side AWS account ID log redaction ([#327](https://github.com/kubernetes-sigs/aws-iam-authenticator/pull/327), @micahhausler)

## Docker Images

Note: You must log in with the registry ID and your role must have the necessary ECR privileges:
```
$(aws ecr get-login --no-include-email --region us-west-2 --registry-ids 602401143452)
```

* `docker pull 602401143452.dkr.ecr.us-west-2.amazonaws.com/amazon/aws-iam-authenticator:v0.5.2-debian-jessie`
* `docker pull 602401143452.dkr.ecr.us-west-2.amazonaws.com/amazon/aws-iam-authenticator:v0.5.2-alpine-3.7`
* `docker pull 602401143452.dkr.ecr.us-west-2.amazonaws.com/amazon/aws-iam-authenticator:v0.5.2-debian-stretch`
* `docker pull 602401143452.dkr.ecr.us-west-2.amazonaws.com/amazon/aws-iam-authenticator:v0.5.2-amazonlinux-2`
* `docker pull 602401143452.dkr.ecr.us-west-2.amazonaws.com/amazon/aws-iam-authenticator:v0.5.2-alpine-3.6`
* `docker pull 602401143452.dkr.ecr.us-west-2.amazonaws.com/amazon/aws-iam-authenticator:v0.5.2-scratch`
````
