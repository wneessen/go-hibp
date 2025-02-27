// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev> et al
//
// SPDX-License-Identifier: MIT

package hibp

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const (
	// ServerResponsePastesAccountExists represents the filename of the test data indicating an existing
	// account for pastes.
	ServerResponsePastesAccountExists = "testdata/pastes-account-exist.txt"

	// ServerResponsePastesAccountExistsBroken represents the filename of the test data for a broken response
	// indicating an account exists.
	ServerResponsePastesAccountExistsBroken = "testdata/pastes-account-exist-broken.txt"
)

func TestPasteAPI_PastedAccount(t *testing.T) {
	apiKey := os.Getenv("HIBP_API_KEY")
	if apiKey == "" {
		t.SkipNow()
	}
	t.Run("account-exists is found in pastes", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponsePastesAccountExists))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		pastes, _, err := hc.PasteAPI.PastedAccount("account-exists@hibp-integration-tests.com")
		if err != nil {
			t.Errorf("failed to get pasted account details: %s", err)
		}
		if len(pastes) != 1 {
			t.Fatalf("expected %d paste(s), got %d", 1, len(pastes))
		}
		paste := pastes[0]
		if !paste.Present() {
			t.Error("paste is expected to be present, but is not")
		}
		if !strings.EqualFold(paste.Title, "nmd") {
			t.Errorf("paste title is expected to be 'nmd', but is %q", paste.Title)
		}
	})
	t.Run("opt-out is not found in pastes", func(t *testing.T) {
		server := httptest.NewServer(newTestFailureHandler(t, http.StatusNotFound))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		pastes, _, err := hc.PasteAPI.PastedAccount("opt-out-breach@hibp-integration-tests.com")
		if err != nil {
			t.Errorf("failed to get pasted account details: %s", err)
		}
		if len(pastes) != 0 {
			t.Error("expected no pastes to be returned, but got some")
		}
	})
	t.Run("pasted account fails on broken JSON", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponsePastesAccountExistsBroken))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.PasteAPI.PastedAccount("account-exists@hibp-integration-tests.com")
		if err == nil {
			t.Error("expected pasted account request to fail on broken JSON")
		}
	})
	t.Run("pasted account with empty account id fails", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponsePastesAccountExists))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.PasteAPI.PastedAccount("")
		if err == nil {
			t.Error("expected pasted account request to fail with empty account id")
		}
		if !errors.Is(err, ErrNoAccountID) {
			t.Errorf("expected error to be %q, got %q", ErrNoAccountID, err)
		}
	})
	t.Run("pasted account fails on HTTP error", func(t *testing.T) {
		server := httptest.NewServer(newTestFailureHandler(t, http.StatusInternalServerError))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.PasteAPI.PastedAccount("account-exists@hibp-integration-tests.com")
		if err == nil {
			t.Error("expected pasted account request to fail on HTTP error")
		}
	})
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
