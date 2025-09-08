package errutil

import (
	"errors"
)

var ErrNotMapped = errors.New("identity is not mapped")

var ErrIDAndARNMismatch = errors.New("ARN does not match User ID")
