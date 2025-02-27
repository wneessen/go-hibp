// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev> et al
//
// SPDX-License-Identifier: MIT

package hibp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	t.Run("return a HIBP client", func(t *testing.T) {
		hc := New()
		if hc.ua != DefaultUserAgent {
			t.Errorf("hibp client default user agent was not set properly. Expected %s, got: %s",
				DefaultUserAgent, hc.ua)
		}
		if hc.PwnedPassAPI == nil {
			t.Fatalf("hibp client pwned password API is nil")
		}
		if hc.PwnedPassAPI.hibp == nil {
			t.Fatalf("hibp client pwned password API client reference is nil")
		}
		if hc.PwnedPassAPIOpts == nil {
			t.Fatalf("hibp client pwned password options is nil")
		}
		if hc.PwnedPassAPIOpts.WithPadding {
			t.Error("expected pwned password padding to be disabled by default")
		}
		if hc.PwnedPassAPIOpts.HashMode != HashModeSHA1 {
			t.Errorf("expected pwned password hash mode to be SHA-1 by default, got: %d", hc.PwnedPassAPIOpts.HashMode)
		}
	})
	t.Run("return a HIBP client with nil option", func(t *testing.T) {
		hc := New(nil)
		if *hc.PwnedPassAPI.hibp != hc {
			t.Errorf("hibp client creation failed")
		}
	})
	t.Run("return a HIBP client with custom HTTP timeout", func(t *testing.T) {
		hc := New(WithHTTPTimeout(time.Second * 10))
		if hc.to != time.Second*10 {
			t.Errorf("hibp client timeout option was not set properly. Expected %d, got: %d",
				time.Second*10, hc.to)
		}
	})
	t.Run("return a HIBP client with PwnedPassword padding enabled", func(t *testing.T) {
		hc := New(WithPwnedPadding())
		if !hc.PwnedPassAPIOpts.WithPadding {
			t.Errorf("hibp client pwned padding option was not set properly. Expected %t, got: %t",
				true, hc.PwnedPassAPIOpts.WithPadding)
		}
	})
	t.Run("return a HIBP client with PwnedPassword with NTLM hashes instead of SHA-1", func(t *testing.T) {
		hc := New(WithPwnedNTLMHash())
		if hc.PwnedPassAPIOpts.HashMode != HashModeNTLM {
			t.Errorf("hibp client NTLM hash mode option was not set properly. Expected %d, got: %d",
				HashModeNTLM, hc.PwnedPassAPIOpts.HashMode)
		}
	})
	t.Run("return a HIBP client with API key set", func(t *testing.T) {
		apiKey := os.Getenv("HIBP_API_KEY")
		if apiKey == "" {
			t.SkipNow()
		}
		hc := New(WithAPIKey(apiKey))
		if hc.ak != apiKey {
			t.Errorf("hibp client API key was not set properly. Expected %s, got: %s",
				apiKey, hc.ak)
		}
	})
	t.Run("return a HIBP client with custom user agent", func(t *testing.T) {
		userAgent := fmt.Sprintf("customUA v%s", Version)
		hc := New(WithUserAgent(userAgent))
		if hc.ua != userAgent {
			t.Errorf("hibp client custom user agent was not set properly. Expected %s, got: %s",
				userAgent, hc.ua)
		}
	})
	t.Run("return a HIBP client with an empty user agent", func(t *testing.T) {
		hc := New(WithUserAgent(""))
		if hc.ua != DefaultUserAgent {
			t.Errorf("hibp client custom user agent was not set properly. Expected %s, got: %s",
				DefaultUserAgent, hc.ua)
		}
	})
	t.Run("return a HIBP client with custom HTTP client", func(t *testing.T) {
		hc := New(WithHTTPClient(newTestClient(t, "https://example.com")))
		if _, ok := hc.hc.(*testClient); !ok {
			t.Errorf("hibp client custom http client option was not set properly. Expected *HTTPClient, got: %T",
				hc.hc)
		}
	})
	t.Run("return a HIBP client with a custom logger", func(t *testing.T) {
		hc := New()
		if hc.logger != nil {
			t.Errorf("hibp client logger was not nil. Expected nil, got: %p", hc.logger)
		}

		customerLogger := &bufio.Writer{}
		hc = New(WithLogger(customerLogger))
		if hc.logger != customerLogger {
			t.Errorf("hibp client custom logger was not set properly. Expected %p, got: %p",
				customerLogger, hc.logger)
		}
		hc = New(WithLogger(nil))
		if hc.logger != nil {
			t.Errorf("hibp client custom logger was not set properly. Expected nil, got: %p", hc.logger)
		}
	})
}

// TestClient_integration_tests performs integration tests against the online HIBP API instead of
// the mocked test server.
func TestClient_integration_tests(t *testing.T) {
	apiKey := os.Getenv("HIBP_API_KEY")
	t.Run("PwnedPassAPI CheckPassword", func(t *testing.T) {
		hc := New(WithLogger(newTestLogger(t)), WithRateLimitSleep())
		m, _, err := hc.PwnedPassAPI.CheckPassword("test")
		if err != nil {
			t.Errorf("CheckPassword failed: %s", err)
		}
		if m.Count == 0 {
			t.Error("CheckPassword returned a zero count for a leaked password")
		}
	})
	t.Run("BreachAPI Breaches", func(t *testing.T) {
		hc := New(WithLogger(newTestLogger(t)), WithRateLimitSleep())
		breaches, _, err := hc.BreachAPI.Breaches()
		if err != nil {
			t.Errorf("Breaches failed: %s", err)
		}
		if len(breaches) == 0 {
			t.Error("Breaches returned an empty list")
		}
	})
	t.Run("BreachAPI BreachByName", func(t *testing.T) {
		hc := New(WithLogger(newTestLogger(t)), WithRateLimitSleep())
		breach, _, err := hc.BreachAPI.BreachByName("Adobe")
		if err != nil {
			t.Errorf("BreachByName failed: %s", err)
		}
		if !strings.EqualFold(breach.Name, "Adobe") {
			t.Errorf("BreachByName returned an unexpected breach name: %s", breach.Name)
		}
		if !breach.IsVerified {
			t.Errorf("BreachByName returned an unverified breach, expected verified")
		}
		if !strings.EqualFold(breach.Domain, "adobe.com") {
			t.Errorf("BreachByName returned an unexpected breach domain: %s", breach.Domain)
		}
	})
	t.Run("BreachAPI LatestBreach", func(t *testing.T) {
		hc := New(WithLogger(newTestLogger(t)), WithRateLimitSleep())
		breach, _, err := hc.BreachAPI.LatestBreach()
		if err != nil {
			t.Errorf("LatestBreach failed: %s", err)
		}
		if !breach.Present() {
			t.Error("LatestBreach did not return a breach")
		}
	})
	t.Run("BreachAPI DataClasses", func(t *testing.T) {
		hc := New(WithLogger(newTestLogger(t)), WithRateLimitSleep())
		classes, _, err := hc.BreachAPI.DataClasses()
		if err != nil {
			t.Errorf("DataClasses failed: %s", err)
		}
		if len(classes) == 0 {
			t.Error("DataClasses returned an empty list")
		}
	})
	t.Run("BreachAPI SubscribedDomains", func(t *testing.T) {
		if apiKey == "" {
			t.SkipNow()
		}
		hc := New(WithLogger(newTestLogger(t)), WithAPIKey(apiKey), WithRateLimitSleep())
		domains, _, err := hc.BreachAPI.SubscribedDomains()
		if err != nil {
			t.Errorf("SubscribedDomains failed: %s", err)
		}
		if len(domains) == 0 {
			t.Error("SubscribedDomains returned an empty list")
		}
	})
	t.Run("PastesAPI PastedAccount exists", func(t *testing.T) {
		if apiKey == "" {
			t.SkipNow()
		}
		hc := New(WithLogger(newTestLogger(t)), WithAPIKey(apiKey), WithRateLimitSleep())
		pastes, _, err := hc.PasteAPI.PastedAccount("account-exists@hibp-integration-tests.com")
		if err != nil {
			t.Errorf("PastedAccount failed: %s", err)
		}
		if len(pastes) != 1 {
			t.Fatalf("PastedAccount was expected to return 1 paste, got: %d", len(pastes))
		}
		paste := pastes[0]
		if !paste.Present() {
			t.Fatal("PastedAccount was expected to return a paste")
		}
		if !strings.EqualFold(paste.Title, "nmd") {
			t.Errorf("PastedAccount returned an unexpected paste title: %s", paste.Title)
		}
	})
	t.Run("PastesAPI PastedAccount does not exist", func(t *testing.T) {
		if apiKey == "" {
			t.SkipNow()
		}
		hc := New(WithLogger(newTestLogger(t)), WithAPIKey(apiKey), WithRateLimitSleep())
		pastes, _, err := hc.PasteAPI.PastedAccount("opt-out-breach@hibp-integration-tests.com")
		if err != nil {
			t.Errorf("PastedAccount failed: %s", err)
		}
		if len(pastes) != 0 {
			t.Fatal("PastedAccount was expected to return no pastes")
		}
	})
}

func TestClient_HTTPReq(t *testing.T) {
	t.Run("HTTP GET request preparation succeeds", func(t *testing.T) {
		server := httptest.NewServer(newTestStringHandler(t, "test"))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		req, err := hc.HTTPReq(http.MethodGet, server.URL, map[string]string{"foo": "bar"})
		if err != nil {
			t.Errorf("HTTP GET request failed: %s", err)
		}
		if req.Method != http.MethodGet {
			t.Errorf("HTTP GET request method was not set properly. Expected %s, got: %s",
				http.MethodGet, req.Method)
		}
	})
	t.Run("HTTP POST request preparation fails", func(t *testing.T) {
		server := httptest.NewServer(newTestStringHandler(t, "test"))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, err := hc.HTTPReq(http.MethodPost, server.URL, map[string]string{"foo": "bar"})
		if err == nil {
			t.Error("HTTP POST request preparation was supposed to fail")
		}
		if !errors.Is(err, ErrHTTPRequestMethodUnsupported) {
			t.Errorf("HTTP POST request preparation failed with unexpected error: %s", err)
		}
	})
	t.Run("HTTP request preparation fails on URL parsing error", func(t *testing.T) {
		reqURL := "this://is.invalid.tld/with/invalid/chars/" + string([]byte{0x7f})
		hc := New()
		_, err := hc.HTTPReq(http.MethodGet, reqURL, map[string]string{"foo": "bar"})
		if err == nil {
			t.Error("HTTP GET request was supposed to fail with invalid URL")
		}
	})
}

func TestClient_HTTPResBody(t *testing.T) {
	t.Run("normal HTTP GET request succeeds", func(t *testing.T) {
		server := httptest.NewServer(newTestStringHandler(t, "test"))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		body, resp, err := hc.HTTPResBody(http.MethodGet, server.URL, map[string]string{"foo": "bar"})
		if err != nil {
			t.Errorf("HTTP GET request failed: %s", err)
		}
		if resp == nil {
			t.Fatal("HTTP GET request response was nil")
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("HTTP GET request status code was not 200. Expected 200, got: %d", resp.StatusCode)
		}
		if !strings.EqualFold(string(body), "test\n") {
			t.Errorf("expected HTTP GET request body to be %q, got: %q", "test", body)
		}
	})
	t.Run("HTTP GET request fails with invalid URL", func(t *testing.T) {
		reqURL := "this://is.invalid.tld/with/invalid/chars/" + string([]byte{0x7f})
		hc := New()
		_, _, err := hc.HTTPResBody(http.MethodGet, reqURL, map[string]string{"foo": "bar"})
		if err == nil {
			t.Error("HTTP GET request was supposed to fail with invalid URL")
		}
	})
	t.Run("HTTP GET request fails on HTTP server error", func(t *testing.T) {
		server := httptest.NewServer(newTestFailureHandler(t, http.StatusInternalServerError))
		defer server.Close()
		hc := New()
		_, _, err := hc.HTTPResBody(http.MethodGet, server.URL, map[string]string{"foo": "bar"})
		if err == nil {
			t.Error("HTTP GET request was supposed to fail with HTTP server error")
		}
	})
	t.Run("HTTP GET request fails on HTTP client error", func(t *testing.T) {
		reqURL := "http://invalid.tld/"
		hc := New()
		_, _, err := hc.HTTPResBody(http.MethodGet, reqURL, map[string]string{"foo": "bar"})
		if err == nil {
			t.Error("HTTP GET request was supposed to fail on non-existent URL")
		}
	})
	t.Run("HTTP GET request succeeds with rate limit sleep", func(t *testing.T) {
		run := 0
		server := httptest.NewServer(newTestRetryHandler(t, &run, false))
		defer server.Close()
		hc := New(WithRateLimitSleep(), WithLogger(newTestLogger(t)))
		_, resp, err := hc.HTTPResBody(http.MethodGet, server.URL, map[string]string{"foo": "bar"})
		if err != nil {
			t.Errorf("HTTP GET request failed: %s", err)
		}
		if resp == nil {
			t.Fatal("HTTP GET request response was nil")
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("HTTP GET request status code was not 200. Expected 200, got: %d", resp.StatusCode)
		}
	})
	t.Run("HTTP GET request fails with invalid rate limit response", func(t *testing.T) {
		run := -1
		server := httptest.NewServer(newTestRetryHandler(t, &run, false))
		defer server.Close()
		hc := New(WithRateLimitSleep(), WithLogger(newTestLogger(t)))
		_, _, err := hc.HTTPResBody(http.MethodGet, server.URL, map[string]string{"foo": "bar"})
		if err == nil {
			t.Error("HTTP GET request was supposed to fail with invalid rate limit response")
		}
	})
}

// testLogger is a test logger type that can be used with the WithLogger option in tests.
type testLogger struct {
	t *testing.T
}

// Write satisfies the io.Writer interface for the testLogger type
func (l *testLogger) Write(p []byte) (n int, err error) {
	l.t.Logf("%s", p)
	return len(p), nil
}

// newTestLogger creates a new testLogger instance using the provided testing.T object for logging in tests.
func newTestLogger(t *testing.T) *testLogger {
	return &testLogger{t}
}

// testClient is a HTTP client that satisfies the HTTPClient interface. We use it for
// mocking tests
type testClient struct {
	*http.Client
	url string
}

// Do satisfies the HTTPClient interface for the testClient type. It replaces the request URL
// in the HTTP request with the given url in the testClient.
func (c *testClient) Do(req *http.Request) (*http.Response, error) {
	testURL, err := url.Parse(c.url)
	if err != nil {
		return nil, err
	}
	req.URL = testURL
	return c.Client.Do(req)
}

// newTestClient creates a mock HTTP client for testing purposes with a specified URL and default timeout.
func newTestClient(t *testing.T, url string) *testClient {
	t.Helper()
	client := httpClient(DefaultTimeout)
	return &testClient{client, url}
}

// newTestStringHandler creates an HTTP handler that responds with a predefined string for testing purposes.
// It writes the string to the response and reports errors via the provided testing object.
func newTestStringHandler(t *testing.T, data string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := fmt.Fprintln(w, data)
		if err != nil {
			t.Errorf("http string handler failed to write string to response writer: %s", err)
		}
	})
}

// newTestFileHandler creates an HTTP handler for serving the content of a test file and reports
// errors via the testing object.
func newTestFileHandler(t *testing.T, filename string) http.Handler {
	t.Helper()
	file, err := os.Open(filename)
	if err != nil {
		t.Fatalf("failed to open test file: %s", err)
	}
	buffer := bytes.NewBuffer(nil)
	_, err = io.Copy(buffer, file)
	if err != nil {
		t.Fatalf("failed to read test file to buffer: %s", err)
	}
	if err = file.Close(); err != nil {
		t.Fatalf("failed to close test file: %s", err)
	}
	return newTestStringHandler(t, buffer.String())
}

// newTestFailureHandler returns an HTTP handler for simulating a failure response in tests with the specified
// status code.
func newTestFailureHandler(t *testing.T, code int) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if code == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "3")
		}
		w.WriteHeader(code)
	})
}

// newTestRetryHandler creates an HTTP handler to test retry logic by simulating "Retry-After" responses
// and success cases.
func newTestRetryHandler(t *testing.T, run *int, returnArray bool) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if *run == -1 {
			w.Header().Set("Retry-After", "invalid")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if *run == 0 {
			*run++
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		if returnArray {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	})
}
