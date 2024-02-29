package fileutil

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/aws-iam-authenticator/pkg/metrics"
)

type FileChangeCallBack interface {
	CallBackForFileLoad(dynamicContent []byte) error
	CallBackForFileDeletion() error
}

func waitUntilFileAvailable(filename string, stopCh <-chan struct{}) {
	if _, err := os.Stat(filename); err == nil {
		return
	}
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			logrus.Infof("startLoadDynamicFile: waitUntilFileAvailable exit because get stopCh, filename is %s", filename)
			return
		case <-ticker.C:
			if _, err := os.Stat(filename); err == nil {
				return
			}
		}
	}
}

func loadDynamicFile(filename string, stopCh <-chan struct{}) ([]byte, error) {
	waitUntilFileAvailable(filename, stopCh)
	if content, err := os.ReadFile(filename); err == nil {
		logrus.Infof("LoadDynamicFile: %v is available. content is %s", filename, string(content))
		return content, nil
	} else {
		return nil, err
	}
}

func StartLoadDynamicFile(filename string, callBack FileChangeCallBack, stopCh <-chan struct{}) {
	go wait.Until(func() {
		// start to watch the file change
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			logrus.Errorf("startLoadDynamicFile: failed when call fsnotify.NewWatcher, %+v", err)
			metrics.Get().DynamicFileFailures.Inc()
			return
		}
		defer watcher.Close()
		content, err := loadDynamicFile(filename, stopCh)
		if err != nil {
			return
		}
		err = watcher.Add(filename)
		if err != nil {
			logrus.Errorf("startLoadDynamicFile: could not add file to watcher %v", err)
			metrics.Get().DynamicFileFailures.Inc()
			return
		}
		if err := callBack.CallBackForFileLoad(content); err != nil {
			logrus.Errorf("StartLoadDynamicFile: error in callBackForFileLoad, %v", err)
		}
		for {
			select {
			case <-stopCh:
				logrus.Infof("startLoadDynamicFile: watching exit because stopCh closed, filename is %s", filename)
				return
			case event := <-watcher.Events:
				switch {
				case event.Op&fsnotify.Write == fsnotify.Write, event.Op&fsnotify.Create == fsnotify.Create:
					// reload the access entry file
					logrus.Info("startLoadDynamicFile: got WRITE/CREATE event reload it the memory")
					content, err := loadDynamicFile(filename, stopCh)
					if err != nil {
						logrus.Errorf("StartLoadDynamicFile: error in loadDynamicFile, %v", err)
						return
					}
					if err := callBack.CallBackForFileLoad(content); err != nil {
						logrus.Errorf("StartLoadDynamicFile: error in callBackForFileLoad, %v", err)
					}
				case event.Op&fsnotify.Rename == fsnotify.Rename, event.Op&fsnotify.Remove == fsnotify.Remove:
					logrus.Info("startLoadDynamicFile: got RENAME/REMOVE event")
					// test if the "REMOVE" is triggered by vi or cp cmd
					_, err := os.Stat(filename)
					if os.IsNotExist(err) {
						if err := callBack.CallBackForFileDeletion(); err != nil {
							logrus.Errorf("StartLoadDynamicFile: error in callBackForFileDeletion, %v", err)
						}
					}
					return
				}
			case err := <-watcher.Errors:
				logrus.Errorf("startLoadDynamicFile: watcher.Errors for dynamic file %v", err)
				metrics.Get().DynamicFileFailures.Inc()
				return
			}
		}
	}, time.Second, stopCh)
}

func CalculateTimeDeltaFromUnixInSeconds(from string) (int64, error) {
	startTime, err := strconv.ParseInt(from, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse 'startTime' string: %v", err)
	}

	endTime := time.Now().Unix()

	if startTime > endTime {
		return 0, fmt.Errorf("start timestamp is after end timestamp")
	}

	return endTime - startTime, nil
}
