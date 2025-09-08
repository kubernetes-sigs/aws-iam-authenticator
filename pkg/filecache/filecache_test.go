package filecache

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/google/go-cmp/cmp"
	"github.com/spf13/afero"
)

const (
	testFilename = "/test.yaml"
)

// stubProvider implements credentials.Provider with configurable response values
type stubProvider struct {
	creds aws.Credentials
	err   error
}

var _ aws.CredentialsProvider = &stubProvider{}

func (s *stubProvider) Retrieve(_ context.Context) (aws.Credentials, error) {
	s.creds.Source = "stubProvider"
	return s.creds, s.err
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
func makeCredential() aws.Credentials {
	return aws.Credentials{
		AccessKeyID:     "AKID",
		SecretAccessKey: "SECRET",
		SessionToken:    "TOKEN",
		Source:          "stubProvider",
		CanExpire:       false,
	}
}

func makeExpiringCredential(e time.Time) aws.Credentials {
	return aws.Credentials{
		AccessKeyID:     "AKID",
		SecretAccessKey: "SECRET",
		SessionToken:    "TOKEN",
		Source:          "stubProvider",
		CanExpire:       true,
		Expires:         e,
	}
}

// validateFileCacheProvider ensures that the cache provider is properly initialized
func validateFileCacheProvider(t *testing.T, p *FileCacheProvider, err error, c aws.CredentialsProvider) {
	t.Helper()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if p.provider != c {
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
	if err := os.Setenv(key, value); err != nil {
		t.Fatalf("Failed to set env var %s: %v", key, err)
	}
	return func() {
		if old == "" {
			if err := os.Unsetenv(key); err != nil {
				t.Fatalf("Failed to unset env var %s: %v", key, err)
			}
		} else {
			if err := os.Setenv(key, old); err != nil {
				t.Fatalf("Failed to set env var %s: %v", key, err)
			}
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
	provider := &stubProvider{}

	tfs, tfl := getMocks()

	p, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", provider,
		WithFilename(testFilename),
		WithFs(tfs),
		WithFileLockerCreator(func(string) FileLocker {
			return tfl
		}))
	validateFileCacheProvider(t, p, err, provider)
	if p.cachedCredential.HasKeys() {
		t.Errorf("missing cache file should result in empty cached credential")
	}
}

func TestNewFileCacheProvider_BadPermissions(t *testing.T) {
	provider := &stubProvider{}

	tfs, _ := getMocks()
	// afero.MemMapFs always returns tempfile FileInfo,
	// so we manually set the response to the Stat() call
	tfs.fileinfo = &testFileInfo{mode: 0777}

	// bad permissions
	_, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", provider,
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
	provider := &stubProvider{}

	tfs, tfl := getMocks()
	if _, err := tfs.Create(testFilename); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// unable to lock
	tfl.success = false
	tfl.err = errors.New("lock stuck, needs wd-40")

	_, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", provider,
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
	provider := &stubProvider{}

	tfs, tfl := getMocks()
	if _, err := tfs.Create(testFilename); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	tfl.err = fmt.Errorf("open %s: permission denied", testFilename)
	tfl.success = false

	_, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", provider,
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
	provider := &stubProvider{}

	tfs, tfl := getMocks()
	if _, err := tfs.Create(testFilename); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	_, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", provider,
		WithFilename(testFilename),
		WithFs(tfs),
		WithFileLockerCreator(func(string) FileLocker {
			if err := afero.WriteFile(
				tfs,
				testFilename,
				[]byte("invalid: yaml: file"),
				0700); err != nil {
				t.Fatalf("Failed to write test file: %v", err)
			}
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
	provider := &stubProvider{}

	tfs, tfl := getMocks()

	// successfully parse existing but empty cache file
	p, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", provider,
		WithFilename(testFilename),
		WithFs(tfs),
		WithFileLockerCreator(func(string) FileLocker {
			if _, err := tfs.Create(testFilename); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}
			return tfl
		}))
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
		return
	}
	validateFileCacheProvider(t, p, err, provider)
	if p.cachedCredential.HasKeys() {
		t.Errorf("empty cache file should result in empty cached credential")
	}
}

func TestNewFileCacheProvider_ExistingCluster(t *testing.T) {
	provider := &stubProvider{}

	tfs, tfl := getMocks()
	if _, err := tfs.Create(testFilename); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// successfully parse existing cluster without matching arn
	p, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", provider,
		WithFilename(testFilename),
		WithFs(tfs),
		WithFileLockerCreator(func(string) FileLocker {
			if err := afero.WriteFile(
				tfs,
				testFilename,
				[]byte(`clusters:
  CLUSTER:
    PROFILE2: {}
`),
				0700); err != nil {
				t.Fatalf("Failed to write test file: %v", err)
			}
			return tfl
		}),
	)
	validateFileCacheProvider(t, p, err, provider)
	if p.cachedCredential.HasKeys() {
		t.Errorf("missing profile in cache file should result in empty cached credential")
	}
}

func TestNewFileCacheProvider_ExistingARN(t *testing.T) {
	provider := &stubProvider{}

	expiry := time.Now().Add(time.Hour * 6)
	content := []byte(`clusters:
  CLUSTER:
    PROFILE:
      ARN:
        accesskeyid: ABC
        secretaccesskey: DEF
        sessiontoken: GHI
        source: JKL
        expires: ` + expiry.Format(time.RFC3339Nano) + `
`)
	tfs, tfl := getMocks()
	if _, err := tfs.Create(testFilename); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// successfully parse cluster with matching arn
	p, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", provider,
		WithFilename(testFilename),
		WithFs(tfs),
		WithFileLockerCreator(func(string) FileLocker {
			if _, err := tfs.Create(testFilename); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}
			if err := afero.WriteFile(tfs, testFilename, content, 0700); err != nil {
				t.Fatalf("Failed to write test file: %v", err)
			}
			return tfl
		}),
	)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
		return
	}
	validateFileCacheProvider(t, p, err, provider)
	if p.cachedCredential.AccessKeyID != "ABC" || p.cachedCredential.SecretAccessKey != "DEF" ||
		p.cachedCredential.SessionToken != "GHI" || p.cachedCredential.Source != "JKL" {
		t.Errorf("cached credential not extracted correctly, got %v", p.cachedCredential)
	}

	if p.cachedCredential.Expired() {
		t.Errorf("Cached credential should not be expired")
	}

	if p.ExpiresAt() != p.cachedCredential.Expires {
		t.Errorf("Credential expiration time is not correct, expected %v, got %v",
			p.cachedCredential.Expires, p.ExpiresAt())
	}
}

func TestFileCacheProvider_Retrieve_NoExpirer(t *testing.T) {
	provider := &stubProvider{
		creds: makeCredential(),
	}

	tfs, tfl := getMocks()
	// don't create the empty cache file, create it in the filelock creator

	p, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", provider,
		WithFilename(testFilename),
		WithFs(tfs),
		WithFileLockerCreator(func(string) FileLocker {
			if _, err := tfs.Create(testFilename); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}
			return tfl
		}),
	)
	validateFileCacheProvider(t, p, err, provider)

	credential, err := p.Retrieve(context.TODO())
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if credential.AccessKeyID != provider.creds.AccessKeyID ||
		credential.SecretAccessKey != provider.creds.SecretAccessKey ||
		credential.SessionToken != provider.creds.SessionToken {
		t.Errorf("Cache did not return provider credential, got %v, expected %v",
			credential, provider.creds)
	}
}

func TestFileCacheProvider_Retrieve_WithExpirer_Unlockable(t *testing.T) {
	expires := time.Now().Add(time.Hour * 6)
	provider := &stubProvider{
		creds: makeExpiringCredential(expires),
	}

	tfs, tfl := getMocks()
	// don't create the empty cache file, create it in the filelock creator

	p, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", provider,
		WithFilename(testFilename),
		WithFs(tfs),
		WithFileLockerCreator(func(string) FileLocker {
			if _, err := tfs.Create(testFilename); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}
			return tfl
		}))
	validateFileCacheProvider(t, p, err, provider)

	// retrieve credential, which will fetch from underlying Provider
	// fail to get write lock
	tfl.success = false
	tfl.err = errors.New("lock stuck, needs wd-40")

	credential, err := p.Retrieve(context.TODO())
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if credential.AccessKeyID != "AKID" || credential.SecretAccessKey != "SECRET" ||
		credential.SessionToken != "TOKEN" || credential.Source != "stubProvider" {
		t.Errorf("cached credential not extracted correctly, got %v", p.cachedCredential)
	}
}

func TestFileCacheProvider_Retrieve_WithExpirer_Unwritable(t *testing.T) {
	expires := time.Now().Add(time.Hour * 6)
	provider := &stubProvider{
		creds: makeExpiringCredential(expires),
	}

	tfs, tfl := getMocks()
	// don't create the file, let the FileLocker create it

	p, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", provider,
		WithFilename(testFilename),
		WithFs(tfs),
		WithFileLockerCreator(func(string) FileLocker {
			if _, err := tfs.Create(testFilename); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}
			return tfl
		}),
	)
	validateFileCacheProvider(t, p, err, provider)

	credential, err := p.Retrieve(context.TODO())
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if credential.AccessKeyID != provider.creds.AccessKeyID ||
		credential.SecretAccessKey != provider.creds.SecretAccessKey ||
		credential.SessionToken != provider.creds.SessionToken ||
		credential.Source != provider.creds.Source {
		t.Errorf("cached credential not extracted correctly, got %v", p.cachedCredential)
	}

	expectedData := []byte(`clusters:
  CLUSTER:
    PROFILE:
      ARN:
        accesskeyid: AKID
        secretaccesskey: SECRET
        sessiontoken: TOKEN
        source: stubProvider
        canexpire: true
        expires: ` + expires.Format(time.RFC3339Nano) + `
        accountid: ""
`)
	got, err := afero.ReadFile(tfs, testFilename)
	if err != nil {
		t.Errorf("unexpected error reading generated file: %v", err)
	}
	if diff := cmp.Diff(got, expectedData); diff != "" {
		t.Errorf("Wrong data written to cache, %s", diff)
	}
}

func TestFileCacheProvider_Retrieve_WithExpirer_Writable(t *testing.T) {
	expires := time.Now().Add(time.Hour * 6)
	provider := &stubProvider{
		creds: makeExpiringCredential(expires),
	}

	tfs, tfl := getMocks()
	// don't create the file, let the FileLocker create it

	p, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", provider,
		WithFilename(testFilename),
		WithFs(tfs),
		WithFileLockerCreator(func(string) FileLocker {
			if _, err := tfs.Create(testFilename); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}
			return tfl
		}),
	)
	validateFileCacheProvider(t, p, err, provider)

	// retrieve credential, which will fetch from underlying Provider
	// same as TestFileCacheProvider_Retrieve_WithExpirer_Unwritable,
	// but write to disk (code coverage)
	credential, err := p.Retrieve(context.TODO())
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if credential.AccessKeyID != provider.creds.AccessKeyID ||
		credential.SecretAccessKey != provider.creds.SecretAccessKey ||
		credential.SessionToken != provider.creds.SessionToken ||
		credential.Source != provider.creds.Source {
		t.Errorf("cached credential not extracted correctly, got %v", p.cachedCredential)
	}
}

func TestFileCacheProvider_Retrieve_CacheHit(t *testing.T) {
	provider := &stubProvider{}
	currentTime := time.Now()

	tfs, tfl := getMocks()
	if _, err := tfs.Create(testFilename); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// successfully parse cluster with matching arn
	content := []byte(`clusters:
  CLUSTER:
    PROFILE:
      ARN:
        credential:
        accesskeyid: ABC
        secretaccesskey: DEF
        sessiontoken: GHI
        source: JKL
        canexpire: true
        expires: ` + currentTime.Add(time.Hour*6).Format(time.RFC3339Nano) + `
`)
	p, err := NewFileCacheProvider("CLUSTER", "PROFILE", "ARN", provider,
		WithFilename(testFilename),
		WithFs(tfs),
		WithFileLockerCreator(func(string) FileLocker {
			if _, err := tfs.Create(testFilename); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}
			if err := afero.WriteFile(tfs, testFilename, content, 0700); err != nil {
				t.Fatalf("Failed to write test file: %v", err)
			}
			return tfl
		}))
	validateFileCacheProvider(t, p, err, provider)

	credential, err := p.Retrieve(context.TODO())
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if credential.AccessKeyID != "ABC" || credential.SecretAccessKey != "DEF" ||
		credential.SessionToken != "GHI" || credential.Source != "JKL" {
		t.Errorf("cached credential not returned")
	}

	if !p.ExpiresAt().Equal(currentTime.Add(time.Hour * 6)) {
		t.Errorf("unexpected expiration time: got %s, wanted %s",
			p.ExpiresAt().Format(time.RFC3339Nano),
			currentTime.Add(time.Hour*6).Format(time.RFC3339Nano),
		)
	}
}
