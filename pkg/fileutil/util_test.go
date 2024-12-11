package fileutil

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
)

var origFileContent = `
Abbatxt7095
`

var updatedFileContent = `
efgwht2033
`

type testStruct struct {
	callCount       int
	expectedContent string
	mutex           sync.Mutex
}

func (a *testStruct) CallBackForFileLoad(dynamicContent []byte) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.callCount++
	if len(dynamicContent) == 0 {
		return fmt.Errorf("file doesn't contain data")
	}
	a.expectedContent = string(dynamicContent)
	return nil
}

func (a *testStruct) CallBackForFileDeletion() error {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.expectedContent = ""
	return nil
}

func TestLoadDynamicFile(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{
			"abcde",
			"abcde",
		},
		{
			"fghijk",
			"fghijk",
		},
		{
			"xyzopq",
			"xyzopq",
		},
		{
			"eks:test",
			"eks:test",
		},
	}
	stopCh := make(chan struct{})
	testA := &testStruct{}
	f, err := os.CreateTemp("/tmp", "testdata")
	if err != nil {
		t.Errorf("failed to create a local temp file %v", err)
	}
	defer os.Remove(f.Name())

	StartLoadDynamicFile(f.Name(), testA, stopCh)
	defer close(stopCh)
	time.Sleep(2 * time.Second)
	err = os.WriteFile(f.Name(), []byte("test"), 0777)
	if err != nil {
		t.Errorf("failed to update a temp file %s, err: %v", f.Name(), err)
	}
	for {
		time.Sleep(1 * time.Second)
		testA.mutex.Lock()
		if testA.callCount != 3 {
			t.Errorf("load file should fail twice but call count is only %d", testA.callCount)
		}
		if testA.expectedContent == "test" {
			t.Log("read to test")
			testA.mutex.Unlock()
			break
		}
		testA.mutex.Unlock()
	}
	for _, c := range cases {
		updateFile(f.Name(), c.input, t)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		//wait until the file reloaded is handled or context timesout
		wait.Until(func() {
			testA.mutex.Lock()
			defer testA.mutex.Unlock()
			// if the file is reloaded then cancel such that the wait.Until completes
			if testA.expectedContent == c.want {
				cancel()
			}
		}, 100*time.Millisecond, ctx.Done())
		cancel()
		//Validate the content
		if testA.expectedContent != c.want {
			t.Errorf(
				"Unexpected result: TestLoadDynamicFile: got: %s, wanted %s",
				testA.expectedContent,
				c.want,
			)
		}
	}

}

func updateFile(fileName, origFileContent string, t *testing.T) {
	data := []byte(origFileContent)
	err := os.WriteFile(fileName, data, 0600)
	if err != nil {
		t.Errorf("failed to update a temp file %s, err: %v", fileName, err)
	}
}

func TestDeleteDynamicFile(t *testing.T) {
	stopCh := make(chan struct{})
	testA := &testStruct{}
	StartLoadDynamicFile("/tmp/delete.txt", testA, stopCh)
	defer close(stopCh)
	time.Sleep(2 * time.Second)
	os.WriteFile("/tmp/delete.txt", []byte("test"), 0777)
	for {
		time.Sleep(1 * time.Second)
		testA.mutex.Lock()
		if testA.expectedContent == "test" {
			t.Log("read to test")
			testA.mutex.Unlock()
			break
		}
		testA.mutex.Unlock()
	}
	os.Remove("/tmp/delete.txt")
	time.Sleep(2 * time.Second)
	testA.mutex.Lock()
	if testA.expectedContent != "" {
		t.Errorf("failed in TestDeleteDynamicFile")
	}
	testA.mutex.Unlock()
}

func TestCalculateTimeDeltaFromUnixInSeconds(t *testing.T) {
	type args struct {
		startTime string
	}
	cases := []struct {
		input  args
		errexp bool
		sleep  bool
	}{
		{
			args{"1706648530"},
			false,
			false,
		},
		{
			args{"1706648520"},
			false,
			false,
		},
		{
			args{"foo"},
			true,
			false,
		},
		{
			args{"2706648520"},
			true,
			false,
		},
		{
			args{strconv.FormatInt(time.Now().Unix(), 10)},
			false,
			true,
		},
	}

	for _, c := range cases {
		if c.sleep {
			time.Sleep(1 * time.Second)
		}

		out, err := CalculateTimeDeltaFromUnixInSeconds(c.input.startTime)
		if !c.errexp && err != nil {
			t.Errorf("Did not expect error but got err: %v", err)
		} else if c.errexp && err == nil {
			t.Error("Expected error but got nil")
		}

		if !c.errexp && out < 1 {
			t.Errorf("Returned an invalid value: %d", out)
		}
	}
}
