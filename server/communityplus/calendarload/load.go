// Package calendarload provides the standalone calendar load-test boundary.
package calendarload

import (
	"errors"
	"net/http"
)

var ErrUnavailable = errors.New("Community+ calendar load-test provider is unavailable")

func Configure(string) (http.Handler, error) { return nil, ErrUnavailable }

func Close() {}
