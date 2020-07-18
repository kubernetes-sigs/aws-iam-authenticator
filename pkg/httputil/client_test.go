package httputil

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewRateLimitedClient(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/test", testHandler)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	u := ts.URL + "/test"

	// requests are to be throttled if qps+burst < reqs
	// estimated time: reqs / (qps+burst) seconds
	tbs := []struct {
		ctxTimeout time.Duration
		qps        int
		burst      int
		requests   int // concurrent requests
		err        string
	}{
		{
			qps:      1,
			burst:    1,
			requests: 10,
		},
		{
			qps:      15,
			burst:    5,
			requests: 100,
		},
		{
			qps:      8,
			burst:    2,
			requests: 20,
		},
		{
			// 20 concurrent ec2 API requests should exceed 1 QPS before 10ms
			// thus rate limiter returns an error
			ctxTimeout: 10 * time.Millisecond,
			qps:        1,
			burst:      1,
			requests:   20,
			err:        `context deadline`,
			// "Wait(n=1) would exceed context deadline" for requests before timeout
			// "context deadline exceeded" for requests after timeout
		},
	}
	for idx, tt := range tbs {
		cli, err := NewRateLimitedClient(tt.qps, tt.burst)
		if err != nil {
			t.Fatalf("#%d: failed to create a new client (%v)", idx, err)
		}

		start := time.Now()

		errc := make(chan error, tt.requests)
		for i := 0; i < tt.requests; i++ {
			go func() {
				var ctx context.Context
				if tt.ctxTimeout > 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(context.TODO(), tt.ctxTimeout)
					defer cancel()
				} else {
					ctx = context.TODO()
				}
				req, err := http.NewRequest(http.MethodGet, u, nil)
				if err != nil {
					errc <- err
					return
				}
				_, err = cli.Do(req.WithContext(ctx))
				errc <- err
			}()
		}

		failed := false
		for i := 0; i < tt.requests; i++ {
			err = <-errc
			switch {
			case tt.err == "": // expects no error
				if err != nil {
					t.Errorf("#%d-%d: unexpected error %v", idx, i, err)
				}
			case tt.err != "": // expects error
				if err == nil {
					// this means that the request did not get throttled.
					continue
				}
				if !strings.Contains(err.Error(), tt.err) &&
					// TODO: why does this happen even when ctx is not canceled
					// ref. https://github.com/golang/go/issues/36848
					!strings.Contains(err.Error(), "i/o timeout") {
					t.Errorf("#%d-%d: expected %q, got %v", idx, i, tt.err, err)
				}
				failed = true
			}
		}

		if tt.err != "" && !failed {
			t.Fatalf("#%d: expected failure %q, got no error", idx, tt.err)
		}

		if tt.err == "" {
			observedDuration := time.Since(start).Round(time.Second)
			expectedDuration := time.Duration(0)
			if tt.qps+tt.burst < tt.requests {
				expectedDuration = (time.Duration(tt.requests/(tt.qps)) * time.Second)
			}
			if expectedDuration > 0 && observedDuration > expectedDuration {
				t.Fatalf("with rate limit, requests expected duration %v, got %v", expectedDuration, observedDuration)
			}
		}
	}
}

func testHandler(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "GET":
		fmt.Fprint(w, `test`)
	default:
		http.Error(w, "Method Not Allowed", 405)
	}
}
