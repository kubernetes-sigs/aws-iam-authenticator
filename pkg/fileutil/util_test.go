package fileutil

import (
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

var origFileContent = `
Abbatxt7095
`

var updatedFileContent = `
efgwht2033
`

type testStruct struct {
	content         string
	expectedContent string
	mutex           sync.Mutex
}

func (a *testStruct) CallBackForFileLoad(dynamicContent []byte) error {
	a.mutex.Lock()
	a.expectedContent = string(dynamicContent)
	defer a.mutex.Unlock()
	return nil
}

func (a *testStruct) CallBackForFileDeletion() error {
	a.mutex.Lock()
	a.expectedContent = ""
	defer a.mutex.Unlock()
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
	StartLoadDynamicFile("/tmp/util_test.txt", testA, stopCh)
	defer close(stopCh)
	time.Sleep(2 * time.Second)
	os.WriteFile("/tmp/util_test.txt", []byte("test"), 0777)
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
	for _, c := range cases {
		updateFile(testA, c.input, t)
		testA.mutex.Lock()
		if testA.expectedContent != c.want {
			t.Errorf(
				"Unexpected result: TestLoadDynamicFile: got: %s, wanted %s",
				testA.expectedContent,
				c.want,
			)
		}
		testA.mutex.Unlock()
	}
}

func updateFile(testA *testStruct, origFileContent string, t *testing.T) {
	testA.content = origFileContent
	data := []byte(origFileContent)
	err := os.WriteFile("/tmp/util_test.txt", data, 0600)
	if err != nil {
		t.Errorf("failed to create a local file /tmp/util_test.txt")
	}
	time.Sleep(1 * time.Second)
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
