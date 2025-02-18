package hibp

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

// TestNew tests the New() function
func TestNew(t *testing.T) {
	hc := New()
	if *hc.PwnedPassAPI.hibp != hc {
		t.Errorf("hibp client creation failed")
	}
}

// TestNewWithNil tests the New() function with a nil option
func TestNewWithNil(t *testing.T) {
	hc := New(nil)
	if *hc.PwnedPassAPI.hibp != hc {
		t.Errorf("hibp client creation failed")
	}
}

// TestNewWithHttpTimeout tests the New() function with the http timeout option
func TestNewWithHttpTimeout(t *testing.T) {
	hc := New(WithHTTPTimeout(time.Second * 10))
	if hc.to != time.Second*10 {
		t.Errorf("hibp client timeout option was not set properly. Expected %d, got: %d",
			time.Second*10, hc.to)
	}
}

// TestNewWithPwnedPadding tests the New() function with the PwnedPadding option
func TestNewWithPwnedPadding(t *testing.T) {
	hc := New(WithPwnedPadding())
	if !hc.PwnedPassAPIOpts.WithPadding {
		t.Errorf("hibp client pwned padding option was not set properly. Expected %t, got: %t",
			true, hc.PwnedPassAPIOpts.WithPadding)
	}
}

// TestNewWithPwnedNTLMHash tests the New() function with the PwnedPadding option
func TestNewWithPwnedNTLMHash(t *testing.T) {
	hc := New(WithPwnedNTLMHash())
	if hc.PwnedPassAPIOpts.HashMode != HashModeNTLM {
		t.Errorf("hibp client NTLM hash mode option was not set properly. Expected %d, got: %d",
			HashModeNTLM, hc.PwnedPassAPIOpts.HashMode)
	}
	hc = New()
	if hc.PwnedPassAPIOpts.HashMode != HashModeSHA1 {
		t.Errorf("hibp client SHA-1 hash mode option was not set properly. Expected %d, got: %d",
			HashModeSHA1, hc.PwnedPassAPIOpts.HashMode)
	}
}

// TestNewWithApiKey tests the New() function with the API key set
func TestNewWithApiKey(t *testing.T) {
	apiKey := os.Getenv("HIBP_API_KEY")
	hc := New(WithAPIKey(apiKey), WithRateLimitSleep())
	if hc.ak != apiKey {
		t.Errorf("hibp client API key was not set properly. Expected %s, got: %s",
			apiKey, hc.ak)
	}
}

// TestNewWithUserAgent tests the New() function with a custom user agent
func TestNewWithUserAgent(t *testing.T) {
	hc := New()
	if hc.ua != DefaultUserAgent {
		t.Errorf("hibp client default user agent was not set properly. Expected %s, got: %s",
			DefaultUserAgent, hc.ua)
	}

	custUA := fmt.Sprintf("customUA v%s", Version)
	hc = New(WithUserAgent(custUA))
	if hc.ua != custUA {
		t.Errorf("hibp client custom user agent was not set properly. Expected %s, got: %s",
			custUA, hc.ua)
	}

	hc = New(WithUserAgent(""))
	if hc.ua != DefaultUserAgent {
		t.Errorf("hibp client custom user agent was not set properly. Expected %s, got: %s",
			DefaultUserAgent, hc.ua)
	}
}

// TestNewWithLogger tests the New() function with a custom logger
func TestNewWithLogger(t *testing.T) {
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
}

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
