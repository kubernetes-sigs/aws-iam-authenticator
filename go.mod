module sigs.k8s.io/aws-iam-authenticator

go 1.16

require (
	github.com/aws/aws-sdk-go v1.44.145
	github.com/fsnotify/fsnotify v1.4.9
	github.com/gofrs/flock v0.7.0
	github.com/manifoldco/promptui v0.9.0
	github.com/prometheus/client_golang v1.12.1
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.4.0
	github.com/spf13/viper v1.7.0
	golang.org/x/time v0.0.0-20220210224613-90d013bbcef8
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.24.8
	k8s.io/apimachinery v0.24.8
	k8s.io/client-go v0.24.8
	k8s.io/code-generator v0.24.8
	k8s.io/component-base v0.24.8
	k8s.io/sample-controller v0.24.8
	sigs.k8s.io/yaml v1.2.0
)
