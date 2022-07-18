package configmap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	core_v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"

	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
	"sigs.k8s.io/aws-iam-authenticator/pkg/metrics"
)

type MapStore struct {
	mutex sync.RWMutex
	users map[string]config.UserMapping
	roles map[string]config.RoleMapping
	// Used as set.
	awsAccounts map[string]interface{}
	configMap   v1.ConfigMapInterface
}

func New(masterURL, kubeConfig string) (*MapStore, error) {
	clientconfig, err := clientcmd.BuildConfigFromFlags(masterURL, kubeConfig)
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(clientconfig)
	if err != nil {
		return nil, err
	}

	ms := MapStore{}
	ms.configMap = clientset.CoreV1().ConfigMaps("kube-system")
	return &ms, nil
}

// Starts a go routine which will watch the configmap and update the in memory data
// when the values change.
func (ms *MapStore) startLoadConfigMap(stopCh <-chan struct{}) {
	go func() {
		for {
			select {
			case <-stopCh:
				return
			default:
				watcher, err := ms.configMap.Watch(context.TODO(), metav1.ListOptions{
					Watch:         true,
					FieldSelector: fields.OneTermEqualSelector("metadata.name", "aws-auth").String(),
				})
				if err != nil {
					logrus.Errorf("Unable to re-establish watch: %v, sleeping for 5 seconds.", err)
					metrics.Get().ConfigMapWatchFailures.Inc()
					time.Sleep(5 * time.Second)
					continue
				}

				for r := range watcher.ResultChan() {
					switch r.Type {
					case watch.Error:
						logrus.WithFields(logrus.Fields{"error": r}).Error("recieved a watch error")
					case watch.Deleted:
						logrus.Info("Resetting configmap on delete")
						userMappings := make([]config.UserMapping, 0)
						roleMappings := make([]config.RoleMapping, 0)
						awsAccounts := make([]string, 0)
						ms.saveMap(userMappings, roleMappings, awsAccounts)
					case watch.Added, watch.Modified:
						switch cm := r.Object.(type) {
						case *core_v1.ConfigMap:
							if cm.Name != "aws-auth" {
								break
							}
							logrus.Info("Received aws-auth watch event")
							userMappings, roleMappings, awsAccounts, err := ParseMap(cm.Data)
							if err != nil {
								logrus.Errorf("There was an error parsing the config maps.  Only saving data that was good, %+v", err)
							}
							ms.saveMap(userMappings, roleMappings, awsAccounts)
							if err != nil {
								logrus.Error(err)
							}
						}

					}
				}
				logrus.Error("Watch channel closed.")
			}
		}
	}()
}

type ErrParsingMap struct {
	errors []error
}

func (err ErrParsingMap) Error() string {
	return fmt.Sprintf("error parsing config map: %v", err.errors)
}

func ParseMap(m map[string]string) (userMappings []config.UserMapping, roleMappings []config.RoleMapping, awsAccounts []string, err error) {
	errs := make([]error, 0)
	rawUserMappings := make([]config.UserMapping, 0)
	userMappings = make([]config.UserMapping, 0)
	if userData, ok := m["mapUsers"]; ok {
		userJson, err := utilyaml.ToJSON([]byte(userData))
		if err != nil {
			errs = append(errs, err)
		} else {
			err = json.Unmarshal(userJson, &rawUserMappings)
			if err != nil {
				errs = append(errs, err)
			}

			for _, userMapping := range rawUserMappings {
				err = userMapping.Validate()
				if err != nil {
					errs = append(errs, err)
				} else {
					userMappings = append(userMappings, userMapping)
				}
			}
		}
	}

	rawRoleMappings := make([]config.RoleMapping, 0)
	roleMappings = make([]config.RoleMapping, 0)
	if roleData, ok := m["mapRoles"]; ok {
		roleJson, err := utilyaml.ToJSON([]byte(roleData))
		if err != nil {
			errs = append(errs, err)
		} else {
			err = json.Unmarshal(roleJson, &rawRoleMappings)
			if err != nil {
				errs = append(errs, err)
			}

			for _, roleMapping := range rawRoleMappings {
				err = roleMapping.Validate()
				if err != nil {
					errs = append(errs, err)
				} else {
					roleMappings = append(roleMappings, roleMapping)
				}
			}
		}
	}

	awsAccounts = make([]string, 0)
	if accountsData, ok := m["mapAccounts"]; ok {
		err := yaml.Unmarshal([]byte(accountsData), &awsAccounts)
		if err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		logrus.Warnf("Errors parsing configmap: %+v", errs)
		err = ErrParsingMap{errors: errs}
	}
	return userMappings, roleMappings, awsAccounts, err
}

func EncodeMap(userMappings []config.UserMapping, roleMappings []config.RoleMapping, awsAccounts []string) (m map[string]string, err error) {
	m = make(map[string]string)

	if len(userMappings) > 0 {
		body, err := yaml.Marshal(userMappings)
		if err != nil {
			return nil, err
		}
		m["mapUsers"] = string(body)
	}

	if len(roleMappings) > 0 {
		body, err := yaml.Marshal(roleMappings)
		if err != nil {
			return nil, err
		}
		m["mapRoles"] = string(body)
	}

	if len(awsAccounts) > 0 {
		body, err := yaml.Marshal(awsAccounts)
		if err != nil {
			return nil, err
		}
		m["mapAccounts"] = string(body)
	}

	return m, nil
}

func (ms *MapStore) saveMap(
	userMappings []config.UserMapping,
	roleMappings []config.RoleMapping,
	awsAccounts []string) {

	ms.mutex.Lock()
	defer ms.mutex.Unlock()
	ms.users = make(map[string]config.UserMapping)
	ms.roles = make(map[string]config.RoleMapping)
	ms.awsAccounts = make(map[string]interface{})

	for _, user := range userMappings {
		ms.users[user.Key()] = user
	}
	for _, role := range roleMappings {
		ms.roles[role.Key()] = role
	}
	for _, awsAccount := range awsAccounts {
		ms.awsAccounts[awsAccount] = nil
	}
}

// UserNotFound is the error returned when the user is not found in the config map.
var UserNotFound = errors.New("User not found in configmap")

// RoleNotFound is the error returned when the role is not found in the config map.
var RoleNotFound = errors.New("Role not found in configmap")

func (ms *MapStore) UserMapping(arn string) (config.UserMapping, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()
	for _, user := range ms.users {
		if user.Matches(arn) {
			return user, nil
		}
	}
	return config.UserMapping{}, UserNotFound
}

func (ms *MapStore) RoleMapping(arn string) (config.RoleMapping, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()
	for _, role := range ms.roles {
		if role.Matches(arn) {
			return role, nil
		}
	}
	return config.RoleMapping{}, RoleNotFound
}

func (ms *MapStore) AWSAccount(id string) bool {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()
	_, ok := ms.awsAccounts[id]
	return ok
}
