module sigs.k8s.io/aws-iam-authenticator/tests/e2e

go 1.25.3

require (
	github.com/onsi/ginkgo/v2 v2.27.1
	github.com/onsi/gomega v1.38.2
	k8s.io/api v0.34.1
	k8s.io/apimachinery v0.34.1
	k8s.io/client-go v0.34.1
	k8s.io/kubernetes v1.34.1
)

require (
	github.com/Masterminds/semver/v3 v3.4.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/emicklei/go-restful/v3 v3.13.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-openapi/jsonpointer v0.22.1 // indirect
	github.com/go-openapi/jsonreference v0.21.2 // indirect
	github.com/go-openapi/swag v0.25.1 // indirect
	github.com/go-openapi/swag/cmdutils v0.25.1 // indirect
	github.com/go-openapi/swag/conv v0.25.1 // indirect
	github.com/go-openapi/swag/fileutils v0.25.1 // indirect
	github.com/go-openapi/swag/jsonname v0.25.1 // indirect
	github.com/go-openapi/swag/jsonutils v0.25.1 // indirect
	github.com/go-openapi/swag/loading v0.25.1 // indirect
	github.com/go-openapi/swag/mangling v0.25.1 // indirect
	github.com/go-openapi/swag/netutils v0.25.1 // indirect
	github.com/go-openapi/swag/stringutils v0.25.1 // indirect
	github.com/go-openapi/swag/typeutils v0.25.1 // indirect
	github.com/go-openapi/swag/yamlutils v0.25.1 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/gnostic-models v0.7.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/pprof v0.0.0-20250403155104-27863c87afa6 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_golang v1.23.2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.67.1 // indirect
	github.com/prometheus/procfs v0.19.1 // indirect
	github.com/spf13/cobra v1.10.1 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.opentelemetry.io/otel v1.38.0 // indirect
	go.opentelemetry.io/otel/trace v1.38.0 // indirect
	go.uber.org/automaxprocs v1.6.0 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/mod v0.29.0 // indirect
	golang.org/x/net v0.46.0 // indirect
	golang.org/x/oauth2 v0.32.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/term v0.36.0 // indirect
	golang.org/x/text v0.30.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	golang.org/x/tools v0.38.0 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
	gopkg.in/evanphx/json-patch.v4 v4.13.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	k8s.io/apiserver v0.34.1 // indirect
	k8s.io/component-base v0.34.1 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
	k8s.io/kube-openapi v0.0.0-20250710124328-f3f2b991d03b // indirect
	k8s.io/pod-security-admission v0.34.1 // indirect
	k8s.io/utils v0.0.0-20250604170112-4c0f3b243397 // indirect
	sigs.k8s.io/json v0.0.0-20241014173422-cfa47c3a1cc8 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/structured-merge-diff/v6 v6.3.0 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
)

replace (
	k8s.io/api => k8s.io/api v0.34.1
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.34.1
	k8s.io/apimachinery => k8s.io/apimachinery v0.34.1
	k8s.io/apiserver => k8s.io/apiserver v0.34.1
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.34.1
	k8s.io/client-go => k8s.io/client-go v0.34.1
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.34.1
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.34.1
	k8s.io/code-generator => k8s.io/code-generator v0.34.1
	k8s.io/component-base => k8s.io/component-base v0.34.1
	k8s.io/component-helpers => k8s.io/component-helpers v0.34.1
	k8s.io/controller-manager => k8s.io/controller-manager v0.34.1
	k8s.io/cri-api => k8s.io/cri-api v0.34.1
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.34.1
	k8s.io/dynamic-resource-allocation => k8s.io/dynamic-resource-allocation v0.34.1
	k8s.io/kms => k8s.io/kms v0.34.1
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.34.1
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.34.1
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.34.1
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.34.1
	k8s.io/kubectl => k8s.io/kubectl v0.34.1
	k8s.io/kubelet => k8s.io/kubelet v0.34.1
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.34.1
	k8s.io/metrics => k8s.io/metrics v0.34.1
	k8s.io/mount-utils => k8s.io/mount-utils v0.34.1
	k8s.io/pod-security-admission => k8s.io/pod-security-admission v0.34.1
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.34.1
	k8s.io/sample-cli-plugin => k8s.io/sample-cli-plugin v0.34.1
	k8s.io/sample-controller => k8s.io/sample-controller v0.34.1
)
