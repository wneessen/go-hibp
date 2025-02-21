// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev> et al
//
// SPDX-License-Identifier: MIT

package hibp

import (
	"errors"
	"fmt"
	"os"
	"testing"
)

// TestPasteAPI_PastedAccount tests the PastedAccount() method of the pastes API
func TestPasteAPI_PastedAccount(t *testing.T) {
	testTable := []struct {
		testName    string
		accountName string
		isPasted    bool
		shouldFail  bool
	}{
		{
			"account-exists is found in pastes", "account-exists@hibp-integration-tests.com",
			true, false,
		},
		{
			"opt-out is not found in pastes", "opt-out-breach@hibp-integration-tests.com",
			false, true,
		},
		{"empty account name", "", false, true},
	}

	apiKey := os.Getenv("HIBP_API_KEY")
	if apiKey == "" {
		t.SkipNow()
	}
	hc := New(WithAPIKey(apiKey), WithRateLimitSleep())
	for _, tc := range testTable {
		t.Run(tc.testName, func(t *testing.T) {
			pasteDetails, _, err := hc.PasteAPI.PastedAccount(tc.accountName)
			if err != nil && !tc.shouldFail {
				t.Error(err)
				return
			}

			if pasteDetails == nil && tc.isPasted {
				t.Errorf("paste for the account %q is expected, but returned 0 results.",
					tc.accountName)
			}
			if pasteDetails != nil && !tc.isPasted {
				t.Errorf("paste for the account %q is expected to be not found, but returned paste details.",
					tc.accountName)
			}
		})
	}
}

// TestPasteAPI_PastedAccount_WithFailedHTTP tests the PastedAccount() method of the pastes API with a failing HTTP request
func TestPasteAPI_PastedAccount_WithFailedHTTP(t *testing.T) {
	apiKey := os.Getenv("HIBP_API_KEY")
	if apiKey == "" {
		t.SkipNow()
	}
	hc := New(WithAPIKey(apiKey), WithRateLimitSleep())
	_, res, err := hc.PasteAPI.PastedAccount("öccount-exists@hibp-integration-tests.com")
	if err == nil {
		t.Errorf("HTTP request for paste should have failed but did not")
		return
	}
	if res == nil {
		t.Errorf("HTTP request for paste should have returned the HTTP response but did not")
	}
}

// TestPasteAPI_PastedAccount_Errors tests the errors defined for the PastedAccount() method
func TestPasteAPI_PastedAccount_Errors(t *testing.T) {
	apiKey := os.Getenv("HIBP_API_KEY")
	if apiKey == "" {
		t.SkipNow()
	}
	hc := New(WithAPIKey(apiKey), WithRateLimitSleep())

	// No account ID given
	_, _, err := hc.PasteAPI.PastedAccount("")
	if err == nil {
		t.Errorf("HTTP request for paste should have failed but did not")
		return
	}
	if !errors.Is(err, ErrNoAccountID) {
		t.Errorf("error response for empty account ID should have been ErrNoAccountID but is not")
	}
}

// ExamplePasteAPI_pastedAccount is a code example to show how to fetch a specific paste
// based on its name from the HIBP pastes API using the PastedAccount() method
func ExamplePasteAPI_pastedAccount() {
	apiKey := os.Getenv("HIBP_API_KEY")
	if apiKey == "" {
		panic("A API key is required for this API")
	}
	hc := New(WithAPIKey(apiKey))
	pd, _, err := hc.PasteAPI.PastedAccount("account-exists@hibp-integration-tests.com")
	if err != nil {
		panic(err)
	}
	for _, p := range pd {
		fmt.Printf("Your account was part of the %q paste\n", p.Title)
	}
}
