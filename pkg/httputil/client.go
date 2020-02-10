// Package httputil implements HTTP utilities.
package httputil

import (
	"fmt"
	"net/http"

	"golang.org/x/time/rate"
)

// NewRateLimitedClient returns a new HTTP client with rate limiter.
func NewRateLimitedClient(qps int, burst int) (*http.Client, error) {
	if qps == 0 {
		return http.DefaultClient, nil
	}
	if burst < 1 {
		return nil, fmt.Errorf("burst expected >0, got %d", burst)
	}
	return &http.Client{
		Transport: &rateLimitedRoundTripper{
			rt: http.DefaultTransport,
			rl: rate.NewLimiter(rate.Limit(qps), burst),
		},
	}, nil
}

type rateLimitedRoundTripper struct {
	rt http.RoundTripper
	rl *rate.Limiter
}

func (rr *rateLimitedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := rr.rl.Wait(req.Context()); err != nil {
		return nil, err
	}
	return rr.rt.RoundTrip(req)
}
