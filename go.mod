module sigs.k8s.io/aws-iam-authenticator

go 1.12

require (
	github.com/aws/aws-sdk-go v1.23.11
	github.com/christopherhein/go-version v0.0.0-20180807222509-fee8dd1f7c24
	github.com/gofrs/flock v0.7.0
	github.com/hashicorp/hcl v0.0.0-20171009174708-42e33e2d55a0 // indirect
	github.com/magiconair/properties v1.7.3 // indirect
	github.com/pelletier/go-toml v1.0.1 // indirect
	github.com/prometheus/client_golang v0.9.2
	github.com/sirupsen/logrus v1.2.0
	github.com/spf13/afero v0.0.0-20171008182726-e67d870304c4 // indirect
	github.com/spf13/cast v1.1.0 // indirect
	github.com/spf13/cobra v0.0.0-20180319062004-c439c4fa0937
	github.com/spf13/jwalterweatherman v0.0.0-20170901151539-12bd96e66386 // indirect
	github.com/spf13/viper v1.0.0
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
