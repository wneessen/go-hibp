package hibp

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// TestNew tests the New() function
func TestNew(t *testing.T) {
	hc := New()
	if *hc.PwnedPassApi.hibp != hc {
		t.Errorf("hibp client creation failed")
	}
}

// TestNewWithNil tests the New() function with a nil option
func TestNewWithNil(t *testing.T) {
	hc := New(nil)
	if *hc.PwnedPassApi.hibp != hc {
		t.Errorf("hibp client creation failed")
	}
}

// TestNewWithHttpTimeout tests the New() function with the http timeout option
func TestNewWithHttpTimeout(t *testing.T) {
	hc := New(WithHttpTimeout(time.Second * 10))
	if hc.to != time.Second*10 {
		t.Errorf("hibp client timeout option was not set properly. Expected %d, got: %d",
			time.Second*10, hc.to)
	}
}

// TestNewWithPwnedPadding tests the New() function with the PwnedPadding option
func TestNewWithPwnedPadding(t *testing.T) {
	hc := New(WithPwnedPadding())
	if !hc.PwnedPassApiOpts.WithPadding {
		t.Errorf("hibp client pwned padding option was not set properly. Expected %v, got: %v",
			true, hc.PwnedPassApiOpts.WithPadding)
	}
}

// TestNewWithApiKey tests the New() function with the API key set
func TestNewWithApiKey(t *testing.T) {
	apiKey := os.Getenv("HIBP_API_KEY")
	hc := New(WithApiKey(apiKey))
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
