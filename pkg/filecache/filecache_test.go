package filecache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/spf13/afero"
)

const (
	testFilename = "/test.yaml"
)

// stubProvider implements credentials.Provider with configurable response values
type stubProvider struct {
	creds   credentials.Value
	expired bool
	err     error
}

var _ credentials.Provider = &stubProvider{}

func (s *stubProvider) Retrieve() (credentials.Value, error) {
	s.expired = false
	s.creds.ProviderName = "stubProvider"
	return s.creds, s.err
}

func (s *stubProvider) IsExpired() bool {
	return s.expired
}

// stubProviderExpirer implements credentials.Expirer with configurable expiration
type stubProviderExpirer struct {
	stubProvider
	expiration time.Time
}

var _ credentials.Expirer = &stubProviderExpirer{}

func (s *stubProviderExpirer) ExpiresAt() time.Time {
	return s.expiration
}

// testFileInfo implements fs.FileInfo with configurable response values
type testFileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
}

var _ fs.FileInfo = &testFileInfo{}

func (fs *testFileInfo) Name() string       { return fs.name }
func (fs *testFileInfo) Size() int64        { return fs.size }
func (fs *testFileInfo) Mode() fs.FileMode  { return fs.mode }
func (fs *testFileInfo) ModTime() time.Time { return fs.modTime }
func (fs *testFileInfo) IsDir() bool        { return fs.Mode().IsDir() }
func (fs *testFileInfo) Sys() interface{}   { return nil }

// testFs wraps afero.Fs with an overridable Stat() method
type testFS struct {
	afero.Fs

	fileinfo fs.FileInfo
	err      error
}

func (t *testFS) Stat(filename string) (fs.FileInfo, error) {
	if t.err != nil {
		return nil, t.err
	}
	if t.fileinfo != nil {
		return t.fileinfo, nil
	}
	return t.Fs.Stat(filename)
}

// testFileLock implements FileLocker with configurable response options
type testFilelock struct {
	ctx        context.Context
	retryDelay time.Duration
	success    bool
	err        error
}

var _ FileLocker = &testFilelock{}

func (l *testFilelock) Unlock() error {
	return nil
}

func (l *testFilelock) TryLockContext(ctx context.Context, retryDelay time.Duration) (bool, error) {
	l.ctx = ctx
	l.retryDelay = retryDelay
	return l.success, l.err
}

func (l *testFilelock) TryRLockContext(ctx context.Context, retryDelay time.Duration) (bool, error) {
	l.ctx = ctx
	l.retryDelay = retryDelay
	return l.success, l.err
}

// getMocks returns a mocked filesystem and FileLocker
func getMocks() (*testFS, *testFilelock) {
	return &testFS{Fs: afero.NewMemMapFs()}, &testFilelock{context.TODO(), 0, true, nil}
}

// makeCredential returns a dummy AWS crdential
func makeCredential() credentials.Value {
	return credentials.Value{
		AccessKeyID:     "AKID",
		SecretAccessKey: "SECRET",
		SessionToken:    "TOKEN",
		ProviderName:    "stubProvider",
	}
}

// validateFileCacheProvider ensures that the cache provider is properly initialized
func validateFileCacheProvider(t *testing.T, p *FileCacheProvider, err error, c *credentials.Credentials) {
	t.Helper()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if p.credentials != c {
		t.Errorf("Credentials not copied")
	}
	if p.cacheKey.clusterID != "CLUSTER" {
		t.Errorf("clusterID not copied")
	}
	if p.cacheKey.profile != "PROFILE" {
		t.Errorf("profile not copied")
	}
	if p.cacheKey.roleARN != "ARN" {
		t.Errorf("roleARN not copied")
	}
}

// testSetEnv sets an env var, and returns a cleanup func
func testSetEnv(t *testing.T, key, value string) func() {
	t.Helper()
	old := os.Getenv(key)
	os.Setenv(key, value)
	return func() {
		if old == "" {
			os.Unsetenv(key)
		} else {
			os.Setenv(key, old)
		}
	}
}

func TestCacheFilename(t *testing.T) {

	c1 := testSetEnv(t, "HOME", "homedir")
	defer c1()
	c2 := testSetEnv(t, "USERPROFILE", "homedir")
	defer c2()

	filename := defaultCacheFilename()
	expected := "homedir/.kube/cache/aws-iam-authenticator/credentials.yaml"
	if filename != expected {
		t.Errorf("Incorrect default cacheFilename, expected %s, got %s",
			expected, filename)
	}

	c3 := testSetEnv(t, "AWS_IAM_AUTHENTICATOR_CACHE_FILE", "special.yaml")
	defer c3()
	filename = defaultCacheFilename()
	expected = "special.yaml"
	if filename != expected {
		t.Errorf("Incorrect custom cacheFilename, expected %s, got %s",
			expected, filename)
	}
}

func TestNewFileCacheProvider_Missing(t *testing.T) {
	c := credentials.NewCredentials(&stubProvider{})

	tfs, tfl := getMocks()

	p, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", c,
		WithFilename(testFilename),
		WithFs(tfs),
		WithFileLockerCreator(func(string) FileLocker {
			return tfl
		}))
	validateFileCacheProvider(t, p, err, c)
	if !p.cachedCredential.IsExpired() {
		t.Errorf("missing cache file should result in expired cached credential")
	}
}

func TestNewFileCacheProvider_BadPermissions(t *testing.T) {
	c := credentials.NewCredentials(&stubProvider{})

	tfs, _ := getMocks()
	// afero.MemMapFs always returns tempfile FileInfo,
	// so we manually set the response to the Stat() call
	tfs.fileinfo = &testFileInfo{mode: 0777}

	// bad permissions
	_, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", c,
		WithFilename(testFilename),
		WithFs(tfs),
	)
	if err == nil {
		t.Errorf("Expected error due to public permissions")
	}
	wantMsg := fmt.Sprintf("cache file %s is not private", testFilename)
	if err.Error() != wantMsg {
		t.Errorf("Incorrect error, wanted '%s', got '%s'", wantMsg, err.Error())
	}
}

func TestNewFileCacheProvider_Unlockable(t *testing.T) {
	c := credentials.NewCredentials(&stubProvider{})

	tfs, tfl := getMocks()
	tfs.Create(testFilename)

	// unable to lock
	tfl.success = false
	tfl.err = errors.New("lock stuck, needs wd-40")

	_, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", c,
		WithFilename(testFilename),
		WithFs(tfs),
		WithFileLockerCreator(func(string) FileLocker {
			return tfl
		}),
	)
	if err == nil {
		t.Errorf("Expected error due to lock failure")
	}
}

func TestNewFileCacheProvider_Unreadable(t *testing.T) {
	c := credentials.NewCredentials(&stubProvider{})

	tfs, tfl := getMocks()
	tfs.Create(testFilename)
	tfl.err = fmt.Errorf("open %s: permission denied", testFilename)
	tfl.success = false

	_, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", c,
		WithFilename(testFilename),
		WithFs(tfs),
		WithFileLockerCreator(func(string) FileLocker {
			return tfl
		}),
	)
	if err == nil {
		t.Errorf("Expected error due to read failure")
		return
	}
	wantMsg := fmt.Sprintf("unable to read lock file %s: open %s: permission denied", testFilename, testFilename)
	if err.Error() != wantMsg {
		t.Errorf("Incorrect error, wanted '%s', got '%s'", wantMsg, err.Error())
	}
}

func TestNewFileCacheProvider_Unparseable(t *testing.T) {
	c := credentials.NewCredentials(&stubProvider{})

	tfs, tfl := getMocks()
	tfs.Create(testFilename)

	_, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", c,
		WithFilename(testFilename),
		WithFs(tfs),
		WithFileLockerCreator(func(string) FileLocker {
			afero.WriteFile(
				tfs,
				testFilename,
				[]byte("invalid: yaml: file"),
				0700)
			return tfl
		}),
	)
	if err == nil {
		t.Errorf("Expected error due to bad yaml")
	}
	wantMsg := fmt.Sprintf("unable to parse file %s: yaml: mapping values are not allowed in this context", testFilename)
	if err.Error() != wantMsg {
		t.Errorf("Incorrect error, wanted '%s', got '%s'", wantMsg, err.Error())
	}
}

func TestNewFileCacheProvider_Empty(t *testing.T) {
	c := credentials.NewCredentials(&stubProvider{})

	tfs, tfl := getMocks()

	// successfully parse existing but empty cache file
	p, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", c,
		WithFilename(testFilename),
		WithFs(tfs),
		WithFileLockerCreator(func(string) FileLocker {
			tfs.Create(testFilename)
			return tfl
		}))
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
		return
	}
	validateFileCacheProvider(t, p, err, c)
	if !p.cachedCredential.IsExpired() {
		t.Errorf("empty cache file should result in expired cached credential")
	}
}

func TestNewFileCacheProvider_ExistingCluster(t *testing.T) {
	c := credentials.NewCredentials(&stubProvider{})

	tfs, tfl := getMocks()
	afero.WriteFile(
		tfs,
		testFilename,
		[]byte(`clusters:
  CLUSTER:
    ARN2: {}
`),
		0700)
	// successfully parse existing cluster without matching arn
	p, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", c,
		WithFilename(testFilename),
		WithFs(tfs),
		WithFileLockerCreator(func(string) FileLocker {
			tfs.Create(testFilename)
			return tfl
		}),
	)
	validateFileCacheProvider(t, p, err, c)
	if !p.cachedCredential.IsExpired() {
		t.Errorf("missing arn in cache file should result in expired cached credential")
	}
}

func TestNewFileCacheProvider_ExistingARN(t *testing.T) {
	c := credentials.NewCredentials(&stubProvider{})

	content := []byte(`clusters:
  CLUSTER:
    PROFILE:
      ARN:
        credential:
          accesskeyid: ABC
          secretaccesskey: DEF
          sessiontoken: GHI
          providername: JKL
        expiration: 2018-01-02T03:04:56.789Z
`)
	tfs, tfl := getMocks()
	tfs.Create(testFilename)

	// successfully parse cluster with matching arn
	p, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", c,
		WithFilename(testFilename),
		WithFs(tfs),
		WithFileLockerCreator(func(string) FileLocker {
			tfs.Create(testFilename)
			afero.WriteFile(tfs, testFilename, content, 0700)
			return tfl
		}),
	)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
		return
	}
	validateFileCacheProvider(t, p, err, c)
	if p.cachedCredential.Credential.AccessKeyID != "ABC" || p.cachedCredential.Credential.SecretAccessKey != "DEF" ||
		p.cachedCredential.Credential.SessionToken != "GHI" || p.cachedCredential.Credential.ProviderName != "JKL" {
		t.Errorf("cached credential not extracted correctly, got %v", p.cachedCredential)
	}
	// fiddle with clock
	p.cachedCredential.currentTime = func() time.Time {
		return time.Date(2017, 12, 25, 12, 23, 45, 678, time.UTC)
	}
	if p.cachedCredential.IsExpired() {
		t.Errorf("Cached credential should not be expired")
	}
	if p.IsExpired() {
		t.Errorf("Cache credential should not be expired")
	}
	expectedExpiration := time.Date(2018, 01, 02, 03, 04, 56, 789000000, time.UTC)
	if p.ExpiresAt() != expectedExpiration {
		t.Errorf("Credential expiration time is not correct, expected %v, got %v",
			expectedExpiration, p.ExpiresAt())
	}
}

func TestFileCacheProvider_Retrieve_NoExpirer(t *testing.T) {
	providerCredential := makeCredential()
	c := credentials.NewCredentials(&stubProvider{
		creds: providerCredential,
	})

	tfs, tfl := getMocks()
	// don't create the empty cache file, create it in the filelock creator

	p, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", c,
		WithFilename(testFilename),
		WithFs(tfs),
		WithFileLockerCreator(func(string) FileLocker {
			tfs.Create(testFilename)
			return tfl
		}),
	)
	validateFileCacheProvider(t, p, err, c)

	credential, err := p.Retrieve()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if credential != providerCredential {
		t.Errorf("Cache did not return provider credential, got %v, expected %v",
			credential, providerCredential)
	}
}

// makeExpirerCredentials returns an expiring credential
func makeExpirerCredentials() (providerCredential credentials.Value, expiration time.Time, c *credentials.Credentials) {
	providerCredential = makeCredential()
	expiration = time.Date(2020, 9, 19, 13, 14, 0, 1000000, time.UTC)
	c = credentials.NewCredentials(&stubProviderExpirer{
		stubProvider{
			creds: providerCredential,
		},
		expiration,
	})
	return
}

func TestFileCacheProvider_Retrieve_WithExpirer_Unlockable(t *testing.T) {
	providerCredential, _, c := makeExpirerCredentials()

	tfs, tfl := getMocks()
	// don't create the empty cache file, create it in the filelock creator

	p, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", c,
		WithFilename(testFilename),
		WithFs(tfs),
		WithFileLockerCreator(func(string) FileLocker {
			tfs.Create(testFilename)
			return tfl
		}))
	validateFileCacheProvider(t, p, err, c)

	// retrieve credential, which will fetch from underlying Provider
	// fail to get write lock
	tfl.success = false
	tfl.err = errors.New("lock stuck, needs wd-40")

	credential, err := p.Retrieve()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if credential != providerCredential {
		t.Errorf("Cache did not return provider credential, got %v, expected %v",
			credential, providerCredential)
	}
}

func TestFileCacheProvider_Retrieve_WithExpirer_Unwritable(t *testing.T) {
	providerCredential, expiration, c := makeExpirerCredentials()

	tfs, tfl := getMocks()
	// don't create the file, let the FileLocker create it

	p, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", c,
		WithFilename(testFilename),
		WithFs(tfs),
		WithFileLockerCreator(func(string) FileLocker {
			tfs.Create(testFilename)
			return tfl
		}),
	)
	validateFileCacheProvider(t, p, err, c)

	credential, err := p.Retrieve()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if credential != providerCredential {
		t.Errorf("Cache did not return provider credential, got %v, expected %v",
			credential, providerCredential)
	}

	expectedData := []byte(`clusters:
  CLUSTER:
    PROFILE:
      ARN:
        credential:
          accesskeyid: AKID
          secretaccesskey: SECRET
          sessiontoken: TOKEN
          providername: stubProvider
        expiration: ` + expiration.Format(time.RFC3339Nano) + `
`)
	got, err := afero.ReadFile(tfs, testFilename)
	if err != nil {
		t.Errorf("unexpected error reading generated file: %v", err)
	}
	if !bytes.Equal(got, expectedData) {
		t.Errorf("Wrong data written to cache, expected: %s, got %s",
			expectedData, got)
	}
}

func TestFileCacheProvider_Retrieve_WithExpirer_Writable(t *testing.T) {
	providerCredential, _, c := makeExpirerCredentials()

	tfs, tfl := getMocks()
	// don't create the file, let the FileLocker create it

	p, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", c,
		WithFilename(testFilename),
		WithFs(tfs),
		WithFileLockerCreator(func(string) FileLocker {
			tfs.Create(testFilename)
			return tfl
		}),
	)
	validateFileCacheProvider(t, p, err, c)

	// retrieve credential, which will fetch from underlying Provider
	// same as TestFileCacheProvider_Retrieve_WithExpirer_Unwritable,
	// but write to disk (code coverage)
	credential, err := p.Retrieve()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if credential != providerCredential {
		t.Errorf("Cache did not return provider credential, got %v, expected %v",
			credential, providerCredential)
	}
}

func TestFileCacheProvider_Retrieve_CacheHit(t *testing.T) {
	c := credentials.NewCredentials(&stubProvider{})
	currentTime := time.Date(2017, 12, 25, 12, 23, 45, 678, time.UTC)

	tfs, tfl := getMocks()
	tfs.Create(testFilename)

	// successfully parse cluster with matching arn
	content := []byte(`clusters:
  CLUSTER:
    PROFILE:
      ARN:
        credential:
          accesskeyid: ABC
          secretaccesskey: DEF
          sessiontoken: GHI
          providername: JKL
        expiration: ` + currentTime.Add(time.Hour*6).Format(time.RFC3339Nano) + `
`)
	p, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", c,
		WithFilename(testFilename),
		WithFs(tfs),
		WithFileLockerCreator(func(string) FileLocker {
			tfs.Create(testFilename)
			afero.WriteFile(tfs, testFilename, content, 0700)
			return tfl
		}))
	validateFileCacheProvider(t, p, err, c)

	// fiddle with clock
	p.cachedCredential.currentTime = func() time.Time { return currentTime }

	credential, err := p.Retrieve()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if credential.AccessKeyID != "ABC" || credential.SecretAccessKey != "DEF" ||
		credential.SessionToken != "GHI" || credential.ProviderName != "JKL" {
		t.Errorf("cached credential not returned")
	}
}
