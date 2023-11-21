package fileutil

import (
	"context"
	"os"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/aws-iam-authenticator/pkg/metrics"
)

type FileChangeCallBack interface {
	CallBackForFileLoad(ctx context.Context, dynamicContent []byte) error
	CallBackForFileDeletion(context.Context) error
}

func waitUntilFileAvailable(ctx context.Context, filename string) {
	if _, err := os.Stat(filename); err == nil {
		return
	}
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			logrus.Infof("startLoadDynamicFile: waitUntilFileAvailable exit because context completed, filename is %s", filename)
			return
		case <-ticker.C:
			if _, err := os.Stat(filename); err == nil {
				return
			}
		}
	}
}

func loadDynamicFile(ctx context.Context, filename string) ([]byte, error) {
	waitUntilFileAvailable(ctx, filename)
	if content, err := os.ReadFile(filename); err == nil {
		logrus.Infof("LoadDynamicFile: %v is available. content is %s", filename, string(content))
		return content, nil
	} else {
		return nil, err
	}
}

func StartLoadDynamicFile(ctx context.Context, filename string, callBack FileChangeCallBack) {
	logrus.Infof("Starting Dynamic File Loader")
	go wait.Until(func() {
		// start to watch the file change
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			logrus.Errorf("startLoadDynamicFile: failed when call fsnotify.NewWatcher, %+v", err)
			metrics.Get().DynamicFileFailures.Inc()
			return
		}
		defer watcher.Close()
		content, err := loadDynamicFile(ctx, filename)
		if err != nil {
			return
		}
		err = watcher.Add(filename)
		if err != nil {
			logrus.Errorf("startLoadDynamicFile: could not add file to watcher %v", err)
			metrics.Get().DynamicFileFailures.Inc()
			return
		}
		if err := callBack.CallBackForFileLoad(ctx, content); err != nil {
			logrus.Errorf("StartLoadDynamicFile: error in callBackForFileLoad, %v", err)
		}
		for {
			select {
			case <-ctx.Done():
				logrus.Infof("startLoadDynamicFile: watching exit because context completed, filename is %s", filename)
				return
			case event := <-watcher.Events:
				switch {
				case event.Op&fsnotify.Write == fsnotify.Write, event.Op&fsnotify.Create == fsnotify.Create:
					// reload the access entry file
					logrus.Info("startLoadDynamicFile: got WRITE/CREATE event reload it the memory")
					content, err := loadDynamicFile(ctx, filename)
					if err != nil {
						logrus.Errorf("StartLoadDynamicFile: error in loadDynamicFile, %v", err)
						return
					}
					if err := callBack.CallBackForFileLoad(ctx, content); err != nil {
						logrus.Errorf("StartLoadDynamicFile: error in callBackForFileLoad, %v", err)
					}
				case event.Op&fsnotify.Rename == fsnotify.Rename, event.Op&fsnotify.Remove == fsnotify.Remove:
					logrus.Info("startLoadDynamicFile: got RENAME/REMOVE event")
					// test if the "REMOVE" is triggered by vi or cp cmd
					_, err := os.Stat(filename)
					if os.IsNotExist(err) {
						if err := callBack.CallBackForFileDeletion(ctx); err != nil {
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
	}, time.Second, ctx.Done())
}
