// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev> et al
//
// SPDX-License-Identifier: MIT

package hibp

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// APIDate is type wrapper for datestamp (without time) returned by the HIBP API
type APIDate struct {
	time.Time
}

// UnmarshalJSON for the APIDate type converts a give date string into a time.Time type
func (a *APIDate) UnmarshalJSON(p []byte) error {
	input := strings.ReplaceAll(string(p), `"`, ``)
	if input == "null" || input == "" {
		return nil
	}

	var parsed time.Time
	var err error
	switch len(input) {
	case 10:
		parsed, err = time.Parse("2006-01-02", input)
	case 19:
		parsed, err = time.Parse("2006-01-02T15:04:05", input)
	default:
		return errors.New("failed to parse JSON string as API date: unknown date format")
	}
	if err != nil {
		return fmt.Errorf("failed to parse JSON string as API date: %s", err)
	}

	a.Time = parsed
	return nil
}
