// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev> et al
//
// SPDX-License-Identifier: MIT

package hibp

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
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
}

/*
func TestClient_HTTPReq(t *testing.T) {
	u1 := "this://is.invalid.tld/with/invalid/chars/" + string([]byte{0x7f})
	u2 := "this://is.invalid.tld/"
	hc := New()
	_, err := hc.HTTPReq(http.MethodGet, u1, map[string]string{"foo": "bar"})
	if err == nil {
		t.Errorf("HTTP GET request was supposed to fail, but didn't")
	}
	_, err = hc.HTTPReq("äöü", u2, map[string]string{"foo": "bar"})
	if err == nil {
		t.Errorf("HTTP GET request was supposed to fail, but didn't")
	}
	_, err = hc.HTTPReq("POST", u2, map[string]string{"foo": "bar"})
	if err != nil {
		t.Errorf("HTTP POST request failed: %s", err)
	}
}

func TestClient_HTTPResBody(t *testing.T) {
	u1 := "this://is.invalid.tld/with/invalid/chars/" + string([]byte{0x7f})
	u2 := "this://is.invalid.tld/"
	hc := New()
	_, _, err := hc.HTTPResBody(http.MethodGet, u1, map[string]string{"foo": "bar"})
	if err == nil {
		t.Errorf("HTTP GET request was supposed to fail, but didn't")
	}
	_, _, err = hc.HTTPResBody("äöü", u2, map[string]string{"foo": "bar"})
	if err == nil {
		t.Errorf("HTTP GET request was supposed to fail, but didn't")
	}
	_, _, err = hc.HTTPResBody("POST", u2, map[string]string{"foo": "bar"})
	if err == nil {
		t.Errorf("HTTP POST request was supposed to fail, but didn't")
	}
}

*/

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
		w.WriteHeader(code)
	})
}
