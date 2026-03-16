// Package errutil defines common errors returned by identity mappers.
package errutil

import (
	"errors"
)

// ErrNotMapped is returned when an identity has no mapping configured.
var ErrNotMapped = errors.New("identity is not mapped")

// ErrIDAndARNMismatch is returned when the ARN does not match the expected user ID.
var ErrIDAndARNMismatch = errors.New("ARN does not match User ID")
