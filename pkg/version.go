/*
Copyright 2020 by the contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package pkg contains build-time version metadata for aws-iam-authenticator, set via ldflags.
package pkg

var (
	// Version is the current release version, set at build time.
	Version = "unversioned"
	// CommitID is the commit ID of the build, set at build time.
	CommitID = ""
	// BuildDate is the date the binary was built, set at build time.
	BuildDate = ""
)
