package crd

import (
	"fmt"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper"
	iamauthenticatorv1alpha1 "sigs.k8s.io/aws-iam-authenticator/pkg/mapper/crd/apis/iamauthenticator/v1alpha1"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper/crd/controller"
	clientset "sigs.k8s.io/aws-iam-authenticator/pkg/mapper/crd/generated/clientset/versioned"
	informers "sigs.k8s.io/aws-iam-authenticator/pkg/mapper/crd/generated/informers/externalversions"
)

type CRDMapper struct {
	*controller.Controller
	// iamInformerFactory is an informer factory that must be Started
	iamInformerFactory informers.SharedInformerFactory
	// iamMappingsSynced is a function to get if the informers have synced
	iamMappingsSynced cache.InformerSynced
	// iamMappingsIndex is a custom indexer which allows for indexing on canonical arns
	iamMappingsIndex cache.Indexer
}

var _ mapper.Mapper = &CRDMapper{}

func NewCRDMapper(cfg config.Config) (*CRDMapper, error) {
	var err error
	var k8sconfig *rest.Config
	var kubeClient kubernetes.Interface
	var iamClient clientset.Interface
	var iamInformerFactory informers.SharedInformerFactory

	if cfg.Master != "" || cfg.Kubeconfig != "" {
		k8sconfig, err = clientcmd.BuildConfigFromFlags(cfg.Master, cfg.Kubeconfig)
	} else {
		k8sconfig, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("can't create kubernetes config: %v", err)
	}

	kubeClient, err = kubernetes.NewForConfig(k8sconfig)
	if err != nil {
		return nil, fmt.Errorf("can't create kubernetes client: %v", err)
	}

	iamClient, err = clientset.NewForConfig(k8sconfig)
	if err != nil {
		return nil, fmt.Errorf("can't create authenticator client: %v", err)
	}

	iamInformerFactory = informers.NewSharedInformerFactory(iamClient, time.Second*36000)

	iamMappingInformer := iamInformerFactory.Iamauthenticator().V1alpha1().IAMIdentityMappings()
	iamMappingsSynced := iamMappingInformer.Informer().HasSynced
	iamMappingsIndex := iamMappingInformer.Informer().GetIndexer()

	ctrl := controller.New(kubeClient, iamClient, iamMappingInformer)

	return &CRDMapper{ctrl, iamInformerFactory, iamMappingsSynced, iamMappingsIndex}, nil
}

func NewCRDMapperWithIndexer(iamMappingsIndex cache.Indexer) *CRDMapper {
	return &CRDMapper{iamMappingsIndex: iamMappingsIndex}
}

func (m *CRDMapper) Name() string {
	return mapper.ModeCRD
}

func (m *CRDMapper) Start(stopCh <-chan struct{}) error {
	m.iamInformerFactory.Start(stopCh)
	go func() {
		// Run starts worker goroutines and blocks
		if err := m.Controller.Run(2, stopCh); err != nil {
			panic(err)
		}
	}()

	return nil
}

func (m *CRDMapper) Map(canonicalARN string) (*config.IdentityMapping, error) {
	canonicalARN = strings.ToLower(canonicalARN)

	var iamidentity *iamauthenticatorv1alpha1.IAMIdentityMapping
	var ok bool
	objects, err := m.iamMappingsIndex.ByIndex("canonicalARN", canonicalARN)
	if err != nil {
		return nil, err
	}

	if len(objects) > 0 {
		for _, obj := range objects {
			iamidentity, ok = obj.(*iamauthenticatorv1alpha1.IAMIdentityMapping)
			if ok {
				break
			}
		}

		if iamidentity != nil {
			return &config.IdentityMapping{
				IdentityARN: canonicalARN,
				Username:    iamidentity.Spec.Username,
				Groups:      iamidentity.Spec.Groups,
			}, nil
		}
	}

	return nil, mapper.ErrNotMapped
}

func (m *CRDMapper) IsAccountAllowed(accountID string) bool {
	return false
}
