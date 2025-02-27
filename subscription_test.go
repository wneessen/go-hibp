// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev> et al
//
// SPDX-License-Identifier: MIT

package hibp

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const (

	// ServerResponseSubscriptionStatus specifies the file path for the subscription status test data.
	ServerResponseSubscriptionStatus = "testdata/subscription-status.txt"

	// ServerResponseSubscriptionStatusBroken specifies the file path for the broken subscription
	// status test data.
	ServerResponseSubscriptionStatusBroken = "testdata/subscription-status-broken.txt"
)

func TestSubscriptionAPI_Status(t *testing.T) {
	apiKey := os.Getenv("HIBP_API_KEY")
	if apiKey == "" {
		t.SkipNow()
	}
	t.Run("subscription status is returned successfully", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseSubscriptionStatus))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		status, _, err := hc.SubscriptionAPI.Status()
		if err != nil {
			t.Errorf("failed to get subscription status: %s", err)
		}
		if !status.Present() {
			t.Error("subscription status is expected to be present")
		}
		if !strings.EqualFold(status.SubscriptionName, "Pwned 1") {
			t.Errorf("subscription description is expected to be 'Pwned 1', but is %q", status.Description)
		}
	})
	t.Run("subscription status fails on HTTP error", func(t *testing.T) {
		server := httptest.NewServer(newTestFailureHandler(t, http.StatusInternalServerError))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.SubscriptionAPI.Status()
		if err == nil {
			t.Error("expected subscription status request to fail on HTTP error")
		}
	})
	t.Run("subscription status fails on broken JSON", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseSubscriptionStatusBroken))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.SubscriptionAPI.Status()
		if err == nil {
			t.Error("expected subscription status request to fail on broken JSON")
		}
	})
	t.Run("subscription status with retry after rate limit succeeds", func(t *testing.T) {
		run := 0
		server := httptest.NewServer(newTestRetryHandler(t, &run, false))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)), WithRateLimitSleep(), WithLogger(newTestLogger(t)))
		_, _, err := hc.SubscriptionAPI.Status()
		if err != nil {
			t.Errorf("failed to get subscription status: %s", err)
		}
	})
	t.Run("subscription status with retry after rate limit fails", func(t *testing.T) {
		run := 0
		server := httptest.NewServer(newTestRetryHandler(t, &run, false))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)), WithLogger(newTestLogger(t)))
		_, hr, err := hc.SubscriptionAPI.Status()
		if err == nil {
			t.Error("expected subscription status request to fail on HTTP error")
		}
		if hr == nil {
			t.Fatal("expected HTTP response to be returned")
		}
		if hr.StatusCode != http.StatusTooManyRequests {
			t.Errorf("expected HTTP status code to be %d, got %d", http.StatusTooManyRequests, hr.StatusCode)
		}
	})
}
