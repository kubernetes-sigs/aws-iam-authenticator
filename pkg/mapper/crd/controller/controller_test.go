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
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/diff"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	core "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"

	iamauthenticator "sigs.k8s.io/aws-iam-authenticator/pkg/mapper/crd/apis/iamauthenticator"
	iamauthenticatorv1alpha1 "sigs.k8s.io/aws-iam-authenticator/pkg/mapper/crd/apis/iamauthenticator/v1alpha1"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper/crd/generated/clientset/versioned/fake"
	informers "sigs.k8s.io/aws-iam-authenticator/pkg/mapper/crd/generated/informers/externalversions"
)

var (
	alwaysReady        = func() bool { return true }
	noResyncPeriodFunc = func() time.Duration { return 0 }
)

type fixture struct {
	t          *testing.T
	client     *fake.Clientset
	kubeclient *k8sfake.Clientset

	iamIdentityLister []*iamauthenticatorv1alpha1.IAMIdentityMapping

	kubeactions []core.Action
	actions     []core.Action

	objects     []runtime.Object
	kubeobjects []runtime.Object
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{}
	f.t = t
	f.objects = []runtime.Object{}
	f.kubeobjects = []runtime.Object{}
	return f
}

func newIAMIdentityMapping(name, arn, username string) *iamauthenticatorv1alpha1.IAMIdentityMapping {
	return &iamauthenticatorv1alpha1.IAMIdentityMapping{
		TypeMeta: metav1.TypeMeta{APIVersion: iamauthenticatorv1alpha1.SchemeGroupVersion.String()},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: iamauthenticatorv1alpha1.IAMIdentityMappingSpec{
			ARN:      arn,
			Username: username,
			Groups:   []string{"system:masters"},
		},
	}
}

func (f *fixture) newController() (*Controller, informers.SharedInformerFactory) {
	f.client = fake.NewSimpleClientset(f.objects...)
	f.kubeclient = k8sfake.NewSimpleClientset(f.kubeobjects...)

	i := informers.NewSharedInformerFactory(f.client, noResyncPeriodFunc())

	c := New(f.kubeclient, f.client, i.Iamauthenticator().V1alpha1().IAMIdentityMappings())

	c.iamMappingsSynced = alwaysReady
	c.recorder = &record.FakeRecorder{}

	for _, f := range f.iamIdentityLister {
		i.Iamauthenticator().V1alpha1().IAMIdentityMappings().Informer().GetIndexer().Add(f)
	}

	return c, i
}

func (f *fixture) run(iamIdentityName string) {
	f.runController(iamIdentityName, true, false)
}

func (f *fixture) runExpectError(iamIdentityName string) {
	f.runController(iamIdentityName, true, true)
}

func (f *fixture) runController(iamIdentityName string, startInformers bool, expectError bool) {
	c, i := f.newController()
	if startInformers {
		stopCh := make(chan struct{})
		defer close(stopCh)
		i.Start(stopCh)
	}

	err := c.syncHandler(iamIdentityName)
	if !expectError && err != nil {
		f.t.Errorf("error syncing iam identity %v", err)
	} else if expectError && err == nil {
		f.t.Error("expected error syncing iam identity, got nil")
	}

	actions := filterInformerActions(f.client.Actions())
	for i, action := range actions {
		if len(f.actions) < i+1 {
			f.t.Errorf("%d unexpected actions: %+v", len(actions)-len(f.actions), actions[i:])
			break
		}
		expectedAction := f.actions[i]
		checkAction(expectedAction, action, f.t)
	}

	if len(f.actions) > len(actions) {
		f.t.Errorf("%d additional expected actions:%+v", len(f.actions)-len(actions), f.actions[len(actions):])
	}

	k8sActions := filterInformerActions(f.kubeclient.Actions())
	for i, action := range k8sActions {
		if len(f.kubeactions) < i+1 {
			f.t.Errorf("%d unexpected actions: %+v", len(k8sActions)-len(f.kubeactions), k8sActions[i:])
			break
		}

		expectedAction := f.kubeactions[i]
		checkAction(expectedAction, action, f.t)
	}

	if len(f.kubeactions) > len(k8sActions) {
		f.t.Errorf("%d additional expected actions:%+v", len(f.kubeactions)-len(k8sActions), f.kubeactions[len(k8sActions):])
	}
}

func checkAction(expected, actual core.Action, t *testing.T) {
	if !(expected.Matches(actual.GetVerb(), actual.GetResource().Resource) && actual.GetSubresource() == expected.GetSubresource()) {
		t.Errorf("expected\n\t%#v\ngot\n\t%#v", expected, actual)
		return
	}

	if reflect.TypeOf(actual) != reflect.TypeOf(expected) {
		t.Errorf("action has wrong type. Expected: %t. Got: %t", expected, actual)
		return
	}

	switch a := actual.(type) {
	case core.CreateAction:
		e, _ := expected.(core.CreateAction)
		expObject := e.GetObject()
		object := a.GetObject()

		if !reflect.DeepEqual(expObject, object) {
			t.Errorf("action %s %s has wrong object\nDiff:\n %s",
				a.GetVerb(), a.GetResource().Resource, diff.ObjectGoPrintDiff(expObject, object))
		}
	case core.UpdateAction:
		e, _ := expected.(core.UpdateAction)
		expObject := e.GetObject()
		object := a.GetObject()

		if !reflect.DeepEqual(expObject, object) {
			t.Errorf("action %s %s has wrong object\nDiff:\n %s",
				a.GetVerb(), a.GetResource().Resource, diff.ObjectGoPrintDiff(expObject, object))
		}
	case core.PatchAction:
		e, _ := expected.(core.PatchAction)
		expPatch := e.GetPatch()
		patch := a.GetPatch()

		if !reflect.DeepEqual(expPatch, patch) {
			t.Errorf("action %s %s has wrong patch\nDiff:\n %s",
				a.GetVerb(), a.GetResource().Resource, diff.ObjectGoPrintDiff(expPatch, patch))
		}
	}
}

func filterInformerActions(actions []core.Action) []core.Action {
	ret := []core.Action{}
	for _, action := range actions {
		if len(action.GetNamespace()) == 0 &&
			(action.Matches("list", "iamidentitymappings") ||
				action.Matches("watch", "iamidentitymappings")) {
			continue
		}
		ret = append(ret, action)
	}

	return ret
}

func (f *fixture) expectUpdateAction(iamidentity *iamauthenticatorv1alpha1.IAMIdentityMapping) {
	action := core.NewRootUpdateAction(schema.GroupVersionResource{Group: iamauthenticator.GroupName, Resource: "iamidentitymappings"}, iamidentity)
	f.actions = append(f.actions, action)
}

func (f *fixture) expectUpdateStatusAction(iamidentity *iamauthenticatorv1alpha1.IAMIdentityMapping) {
	action := core.NewRootUpdateSubresourceAction(schema.GroupVersionResource{Group: iamauthenticator.GroupName, Resource: "iamidentitymappings"}, "status", iamidentity)
	f.actions = append(f.actions, action)
}

func (f *fixture) expectCreateAction(iamidentity *iamauthenticatorv1alpha1.IAMIdentityMapping) {
	action := core.NewRootCreateAction(schema.GroupVersionResource{Group: iamauthenticator.GroupName, Resource: "iamidentitymappings"}, iamidentity)
	f.actions = append(f.actions, action)
}

func getKey(iamidentity *iamauthenticatorv1alpha1.IAMIdentityMapping, t *testing.T) string {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(iamidentity)
	if err != nil {
		t.Errorf("unexpected error getting key for iam identity %v : %v", iamidentity.Name, err)
		return ""
	}
	return key
}

func TestIAMIdentityMappingCreation(t *testing.T) {
	f := newFixture(t)
	iamidentity := newIAMIdentityMapping("test", "arn:aws:iam::XXXXXXXXXXXX:user/AuthorizedUser", "user-1")
	f.iamIdentityLister = append(f.iamIdentityLister, iamidentity)
	f.objects = append(f.objects, iamidentity)

	// Update will always add these parameters
	canonicalizedArn := "arn:aws:iam::xxxxxxxxxxxx:user/authorizeduser"
	iamidentity.Status = iamauthenticatorv1alpha1.IAMIdentityMappingStatus{
		CanonicalARN: canonicalizedArn,
	}

	f.expectUpdateStatusAction(iamidentity)
	f.run(getKey(iamidentity, t))
}
