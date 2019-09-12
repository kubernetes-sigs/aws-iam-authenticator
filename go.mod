module sigs.k8s.io/aws-iam-authenticator

go 1.12

require (
	github.com/aws/aws-sdk-go v1.19.11
	github.com/christopherhein/go-version v0.0.0-20180807222509-fee8dd1f7c24
	github.com/emicklei/go-restful v2.4.0+incompatible // indirect
	github.com/gofrs/flock v0.7.0
	github.com/prometheus/client_golang v0.9.3
	github.com/sirupsen/logrus v1.2.0
	github.com/spf13/cobra v0.0.5
	github.com/spf13/viper v1.4.0
	go.hein.dev/go-version v0.1.0
	gopkg.in/yaml.v2 v2.2.2
	k8s.io/api v0.0.0-20190425012535-181e1f9c52c1
	k8s.io/apiextensions-apiserver v0.0.0-20190426053235-842c4571cde0
	k8s.io/apimachinery v0.0.0-20190612125636-6a5db36e93ad
	k8s.io/client-go v0.0.0-20190425172711-65184652c889
	k8s.io/code-generator v0.0.0-20190419212335-ff26e7842f9d
	k8s.io/component-base v0.0.0-20190612130303-4062e14deebe
	k8s.io/sample-controller v0.0.0-20190425173525-f9c23632fb31
)

replace (
	k8s.io/api => k8s.io/api v0.0.0-20190425012535-181e1f9c52c1
	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20190425132440-17f84483f500
	k8s.io/client-go => k8s.io/client-go v0.0.0-20190425172711-65184652c889
	k8s.io/code-generator => k8s.io/code-generator v0.0.0-20190419212335-ff26e7842f9d
)
