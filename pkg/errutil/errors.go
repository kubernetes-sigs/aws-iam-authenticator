package errutil

import (
	"errors"
)

var ErrNotMapped = errors.New("Identity is not mapped")

var ErrIDAndARNMismatch = errors.New("ARN does not match User ID")
