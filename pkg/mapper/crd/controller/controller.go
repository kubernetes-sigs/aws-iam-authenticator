/*
Copyright 2017 The Kubernetes Authors.
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

package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	"github.com/sirupsen/logrus"

	"sigs.k8s.io/aws-iam-authenticator/pkg/arn"
	iamauthenticatorv1alpha1 "sigs.k8s.io/aws-iam-authenticator/pkg/mapper/crd/apis/iamauthenticator/v1alpha1"
	clientset "sigs.k8s.io/aws-iam-authenticator/pkg/mapper/crd/generated/clientset/versioned"
	iamscheme "sigs.k8s.io/aws-iam-authenticator/pkg/mapper/crd/generated/clientset/versioned/scheme"
	informers "sigs.k8s.io/aws-iam-authenticator/pkg/mapper/crd/generated/informers/externalversions/iamauthenticator/v1alpha1"
	listers "sigs.k8s.io/aws-iam-authenticator/pkg/mapper/crd/generated/listers/iamauthenticator/v1alpha1"
)

const (
	// controllerAgentName is the name the controller appears as in the Event logger
	controllerAgentName = "aws-iam-authenticator"

	// SuccessSynced is used as part of the Event 'reason' when a Identity is synced
	SuccessSynced = "Synced"

	// IdentitySynced is the `message` when an Identity is synced
	IdentitySynced = "Identity synced successfully"
)

// Controller implements the logic for getting and mutating IAMIdentityMappings
type Controller struct {
	// kubeclientset implements the Kubernetes clientset, used for the event recorder
	kubeclientset kubernetes.Interface

	// iamclientset implements the IAMIdentityMapping clientset, used for getting identities
	iamclientset clientset.Interface
	// iamMappingLister implements the lister interface for IAMIdentityMappings
	iamMappingLister listers.IAMIdentityMappingLister
	// iamMappingsSynced is a function to get if the informers have synced
	iamMappingsSynced cache.InformerSynced
	// iamMappingsIndex is a custom indexer which allows for indexing on canonical arns
	iamMappingsIndex cache.Indexer

	// workqueue implements a FIFO queue used for processing items
	workqueue workqueue.RateLimitingInterface
	// recorder implements the Event recorder interface for logging events.
	recorder record.EventRecorder
}

// New will initialize a default controller object
func New(
	kubeclientset kubernetes.Interface,
	iamclientset clientset.Interface,
	iamMappingInformer informers.IAMIdentityMappingInformer) *Controller {

	// Initialize the Scheme
	utilruntime.Must(iamscheme.AddToScheme(scheme.Scheme))

	// Setup event broadcaster
	logrus.Info("creating event broadcaster")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(logrus.Infof)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeclientset.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: controllerAgentName})

	controller := &Controller{
		kubeclientset:     kubeclientset,
		iamclientset:      iamclientset,
		iamMappingLister:  iamMappingInformer.Lister(),
		iamMappingsSynced: iamMappingInformer.Informer().HasSynced,
		workqueue:         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "IAMIdentityMappings"),
		recorder:          recorder,
	}

	logrus.Info("setting up event handlers")
	// adding event handlers to load the informer and convert roles into
	// canonical ARNs, we're ignoring deletes because all checks for roles happen
	// using the in-memory cache which is updated automatically on deletes no further
	// actions are necessary
	iamMappingInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueIAMIdentityMapping,
		UpdateFunc: func(old, new interface{}) {
			controller.enqueueIAMIdentityMapping(new)
		},
	})

	err := iamMappingInformer.Informer().GetIndexer().AddIndexers(cache.Indexers{
		"canonicalARN": IndexIAMIdentityMappingByCanonicalArn,
	})
	if err != nil {
		logrus.WithError(err).Fatal("error adding index")
	}

	controller.iamMappingsIndex = iamMappingInformer.Informer().GetIndexer()

	return controller
}

// Run will implement the loop for processing items
func (c *Controller) Run(threadiness int, stopCh <-chan struct{}) error {
	defer utilruntime.HandleCrash()
	defer c.workqueue.ShutDown()

	logrus.Info("starting aws iam authenticator controller")

	logrus.Info("waiting for informer caches to sync")
	if ok := cache.WaitForCacheSync(stopCh, c.iamMappingsSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	logrus.Info("starting workers")
	for i := 0; i < threadiness; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	logrus.Info("started workers")
	<-stopCh
	logrus.Info("shutting down workers")

	return nil
}

// runWorker loops over each item looking for boolean returns
func (c *Controller) runWorker() {
	for c.processNextWorkItem() {
	}
}

// processNextWorkItem will process each item off the queue
func (c *Controller) processNextWorkItem() bool {
	obj, shutdown := c.workqueue.Get()

	if shutdown {
		return false
	}

	err := func(obj interface{}) error {
		defer c.workqueue.Done(obj)
		var key string
		var ok bool
		if key, ok = obj.(string); !ok {
			c.workqueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}

		if err := c.syncHandler(key); err != nil {
			c.workqueue.AddRateLimited(key)
			return fmt.Errorf("error syncing %s : %s, requeuing", key, err.Error())
		}

		c.workqueue.Forget(obj)
		logrus.Infof("successfully synced %s", key)
		return nil
	}(obj)

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	return true
}

func (c *Controller) syncHandler(key string) (err error) {
	_, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("invalid resource key %s", key))
		return nil
	}

	iamIdentityMapping, err := c.iamMappingLister.Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			utilruntime.HandleError(fmt.Errorf("iam identity mapping %s no longer exists", key))
			return nil
		}
		return err
	}

	// Process items
	if iamIdentityMapping.Spec.ARN != "" {
		iamIdentityMappingCopy := iamIdentityMapping.DeepCopy()

		canonicalizedARN, err := arn.Canonicalize(strings.ToLower(iamIdentityMapping.Spec.ARN))
		if err != nil {
			return err
		}

		iamIdentityMappingCopy.Status.CanonicalARN = canonicalizedARN
		_, err = c.iamclientset.IamauthenticatorV1alpha1().IAMIdentityMappings().UpdateStatus(context.TODO(), iamIdentityMappingCopy, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
	}

	c.recorder.Event(iamIdentityMapping, corev1.EventTypeNormal, SuccessSynced, IdentitySynced)
	return nil
}

// enqueueIAMIdentityMapping will pull in a new IAMIdentityMapping and update it
func (c *Controller) enqueueIAMIdentityMapping(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.workqueue.Add(key)
}

// IndexIAMIdentityMappingByCanonicalArn collects the information for the additional indexer used for finding identities
func IndexIAMIdentityMappingByCanonicalArn(obj interface{}) ([]string, error) {
	iamIdentity, ok := obj.(*iamauthenticatorv1alpha1.IAMIdentityMapping)
	if !ok {
		return []string{}, nil
	}

	canonicalArnStr := iamIdentity.Status.CanonicalARN
	if canonicalArnStr == "" {
		return []string{}, nil
	}

	return []string{canonicalArnStr}, nil
}
