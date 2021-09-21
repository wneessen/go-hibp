package hibp

import (
	"testing"
)

// TestBreaches tests the Breaches() method of the breaches API
func TestBreaches(t *testing.T) {
	hc := New()
	if hc == nil {
		t.Errorf("hibp client creation failed")
		return
	}

	breachList, _, err := hc.BreachApi.Breaches()
	if err != nil {
		t.Error(err)
	}
	if breachList != nil && len(breachList) <= 0 {
		t.Error("breaches list returned 0 results")
	}
}

// TestBreachesWithDomain tests the Breaches() method of the breaches API for a specific domain
func TestBreachesWithDomain(t *testing.T) {
	testTable := []struct {
		testName   string
		domain     string
		isBreached bool
	}{
		{"adobe.com is breached", "adobe.com", true},
		{"example.com is not breached", "example.com", false},
	}

	hc := New()
	if hc == nil {
		t.Error("failed to create HIBP client")
		return
	}

	for _, tc := range testTable {
		t.Run(tc.testName, func(t *testing.T) {
			breachList, _, err := hc.BreachApi.Breaches(WithDomain(tc.domain))
			if err != nil {
				t.Error(err)
			}

			if breachList == nil && tc.isBreached {
				t.Errorf("domain %s is expected to be breached, but returned 0 results.",
					tc.domain)
			}

			breachLen := len(breachList)
			if tc.isBreached && breachLen <= 0 {
				t.Errorf("domain %s is expected to be breached, but returned 0 results.",
					tc.domain)
			}
			if !tc.isBreached && breachLen != 0 {
				t.Errorf("domain %s is expected to be not breached, but returned %d results.",
					tc.domain, breachLen)
			}
		})
	}
}
