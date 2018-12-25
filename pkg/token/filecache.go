package token

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/gofrs/flock"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// A mockable filesystem interface
var f filesystem = osFS{}

type filesystem interface {
	Stat(filename string) (os.FileInfo, error)
	ReadFile(filename string) ([]byte, error)
	WriteFile(filename string, data []byte, perm os.FileMode) error
}

// default os based implementation
type osFS struct {}

func (osFS) Stat(filename string) (os.FileInfo, error) {
	return os.Stat(filename)
}

func (osFS) ReadFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

func (osFS) WriteFile(filename string, data []byte, perm os.FileMode) error {
	return ioutil.WriteFile(filename, data, perm)
}

// A mockable environment interface
var e environment = osEnv{}

type environment interface {
	Getenv(key string) string
	LookupEnv(key string) (string, bool)
}

// default os based implementation
type osEnv struct {}

func (osEnv) Getenv(key string) string {
	return os.Getenv(key)
}

func (osEnv) LookupEnv(key string) (string, bool) {
	return os.LookupEnv(key)
}

// A mockable flock interface
type filelock interface {
	Unlock() error
	TryLockContext(ctx context.Context, retryDelay time.Duration) (bool, error)
	TryRLockContext(ctx context.Context, retryDelay time.Duration) (bool, error)
}

var newFlock = func(filename string) filelock {
	return flock.New(filename)
}

// cacheFile is a map of clusterID/roleARNs to cached tokens
type cacheFile struct {
	// a map of clusterIDs/profiles/roleARNs to cachedTokens
	ClusterMap map[string]map[string]map[string]cacheToken `yaml:"clusters"`
}

// cacheToken is a single cached token entry, along with expiration time
type cacheToken struct {
	Token      credentials.Value
	Expiration time.Time
	// If set will be used by IsExpired to determine the current time.
	// Defaults to time.Now if CurrentTime is not set.  Available for testing
	// to be able to mock out the current time.
	currentTime func() time.Time
}

// IsExpired determines if the cached token has expired
func (t *cacheToken) IsExpired() bool {
	curTime := t.currentTime
	if curTime == nil {
		curTime = time.Now
	}
	return t.Expiration.Before(curTime())
}

// readCacheWhileLocked reads the contents of the token cache and returns the
// parsed yaml as a cacheFile object.  This method must be called while a shared
// lock is held on the filename.
func readCacheWhileLocked(filename string) (cache cacheFile, err error) {
	cache = cacheFile{
		map[string]map[string]map[string]cacheToken{},
	}
	data, err := f.ReadFile(filename)
	if err != nil {
		err = fmt.Errorf("unable to open file %s: %v", filename, err)
		return
	}

	err = yaml.Unmarshal(data, &cache)
	if err != nil {
		err = fmt.Errorf("unable to parse file %s: %v", filename, err)
	}
	return
}

// writeCacheWhileLocked writes the contents of the token cache using the
// yaml marshaled form of the passed cacheFile object.  This method must be
// called while an exclusive lock is held on the filename.
func writeCacheWhileLocked(filename string, cache cacheFile) error {
	data, err := yaml.Marshal(cache)
	if err == nil {
		// write privately owned by the user
		err = f.WriteFile(filename, data, 0600)
	}
	return err
}

// FileCacheProvider is a Provider implementation that wraps an underlying Provider
// (contained in Credentials) and provides caching support for tokens for the
// specified clusterID and roleARN
type FileCacheProvider struct {
	credentials                 *credentials.Credentials // the underlying implementation that has the *real* Provider
	clusterID, profile, roleARN string                   // parameters used to create Provider
	cachedToken                 cacheToken               // the cached token, if it exists
}

// NewFileCacheProvider creates a new Provider implementation that wraps a provided Credentials,
// and works with an on disk cache to speed up token usage when the cached copy is not expired.
// If there are any problems accessing or initializing the cache, an error will be returned, and
// callers should just use the existing credentials provider.
func NewFileCacheProvider(clusterID, profile, roleARN string, creds *credentials.Credentials) (FileCacheProvider, error) {
	filename := CacheFilename()
	cachedToken := cacheToken{}
	if info, err := f.Stat(filename); !os.IsNotExist(err) {
		if info.Mode() & 0077 != 0 {
			// cache file has secret credentials and should only be accessible to the user, refuse to use it.
			return FileCacheProvider{}, fmt.Errorf("cache file %s is not private", filename)
		}

		// do file locking on cache to prevent inconsistent reads
		lock := newFlock(filename)
		defer lock.Unlock()
		// wait up to a second for the file to lock
		ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
		defer cancel()
		ok, err := lock.TryRLockContext(ctx, 250 * time.Millisecond) // try to lock every 1/4 second
		if !ok {
			// unable to lock the cache, something is wrong, refuse to use it.
			return FileCacheProvider{}, fmt.Errorf("unable to read lock file %s: %v", filename, err)
		}

		cache, err := readCacheWhileLocked(filename)
		if err != nil {
			// can't read or parse cache, refuse to use it.
			return FileCacheProvider{}, err
		}

		if _, ok := cache.ClusterMap[clusterID]; ok {
			if _, ok := cache.ClusterMap[clusterID][profile]; ok {
				// we at least have this cluster and profile combo in the map, if no matching roleARN, map will
				// return the zero-value for cacheToken, which expired a long time ago.
				cachedToken = cache.ClusterMap[clusterID][profile][roleARN]
			}
		}
	} else {
		// cache file is missing.  maybe this is the very first run?  continue to use cache.
		_, _ = fmt.Fprintf(os.Stderr, "Cache file %s does not exist.\n", filename)
	}

	return FileCacheProvider{
		creds,
		clusterID,
		profile,
		roleARN,
		cachedToken,
	}, nil
}

// Retrieve() implements the Provider interface, returning the cached token if is not expired,
// otherwise fetching the token from the underlying Provider and caching the results on disk
// with an expiration time.
func (f *FileCacheProvider) Retrieve() (credentials.Value, error) {
	if !f.cachedToken.IsExpired() {
		// use the cached token
		return f.cachedToken.Token, nil
	} else {
		_, _ = fmt.Fprintf(os.Stderr, "No cached token available.  Refreshing...\n")
		// fetch the token from the underlying Provider
		token, err := f.credentials.Get()
		if err == nil {
			if expiration, err := f.credentials.ExpiresAt(); err == nil {
				// underlying provider supports Expirer interface, so we can cache
				filename := CacheFilename()
				// do file locking on cache to prevent inconsistent writes
				lock := newFlock(filename)
				defer lock.Unlock()
				// wait up to a second for the file to lock
				ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
				defer cancel()
				ok, err := lock.TryLockContext(ctx, 250 * time.Millisecond) // try to lock every 1/4 second
				if ok {
					f.cachedToken = cacheToken{
						token,
						expiration,
						nil,
					}
					// don't really care about read error.  Either read the cache, or we create a new cache.
					cache, _ := readCacheWhileLocked(filename)
					if _, ok := cache.ClusterMap[f.clusterID]; !ok {
						// first use of this cluster id
						cache.ClusterMap[f.clusterID] = map[string]map[string]cacheToken{}
					}
					if _, ok := cache.ClusterMap[f.clusterID][f.profile]; !ok {
						// first use of this profile
						cache.ClusterMap[f.clusterID][f.profile] = map[string]cacheToken{}
					}
					cache.ClusterMap[f.clusterID][f.profile][f.roleARN] = f.cachedToken
					err = writeCacheWhileLocked(filename, cache)
					if err != nil {
						// can't write cache, but still return the credential
						_, _ = fmt.Fprintf(os.Stderr, "Unable to update token cache %s: %v\n", filename, err)
					} else {
						_, _ = fmt.Fprintf(os.Stderr, "Updated cached token\n")
					}
				} else {
					// can't get write lock to create/update cache, but still return the credential
					_, _ = fmt.Fprintf(os.Stderr, "Unable to write lock file %s: %v\n", filename, err)
				}
			} else {
				// credential doesn't support expiration time, so can't cache, but still return the credential
				_, _ = fmt.Fprintf(os.Stderr, "Unable to cache token: %v\n", err)
			}
		}
		return token, err
	}
}

// IsExpired() implements the Provider interface, deferring to the cached token first,
// but fall back to the underlying Provider if it is expired.
func (f *FileCacheProvider) IsExpired() bool {
	return f.cachedToken.IsExpired() && f.credentials.IsExpired()
}

// ExpiresAt implements the Expirer interface, and gives access to the expiration time of the token
func (f* FileCacheProvider) ExpiresAt() time.Time {
	return f.cachedToken.Expiration
}

// CacheFilename returns the name of the token cache file, which can either be
// set by environment variable, or use the default of ~/.kube/cache/token.yaml
func CacheFilename() string {
	if filename, ok := e.LookupEnv("AWS_IAM_AUTHENTICATOR_CACHE_FILE"); ok {
		return filename
	} else {
		return filepath.Join(UserHomeDir(), ".kube", "cache", "token.yaml")
	}
}

// UserHomeDir returns the home directory for the user the process is
// running under.
func UserHomeDir() string {
	if runtime.GOOS == "windows" { // Windows
		return e.Getenv("USERPROFILE")
	}

	// *nix
	return e.Getenv("HOME")
}