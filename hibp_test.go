package hibp

import (
	"testing"
	"time"
)

// TestNew tests the New() function
func TestNew(t *testing.T) {
	hc := New()
	if hc == nil {
		t.Errorf("hibp client creation failed")
	}
}

// TestNewWithHttpTimeout tests the New() function
func TestNewWithHttpTimeout(t *testing.T) {
	hc := New(WithHttpTimeout(time.Second * 10))
	if hc == nil {
		t.Errorf("hibp client creation failed")
		return
	}
	if hc.to != time.Second*10 {
		t.Errorf("hibp client timeout option was not set properly. Expected %d, got: %d",
			time.Second*10, hc.to)
	}
}
