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

// TestBreachesWithoutUnverified tests the Breaches() method of the breaches API with the unverified parameter
func TestBreachesWithoutUnverified(t *testing.T) {
	testTable := []struct {
		testName   string
		domain     string
		isBreached bool
		isVerified bool
	}{
		{"adobe.com is breached and verified", "adobe.com", true, true},
		{"parapa.mail.ru is breached and verified", "parapa.mail.ru", true, true},
		{"xiaomi.cn is breached but not verified", "xiaomi.cn", true, false},
	}

	hc := New()
	if hc == nil {
		t.Error("failed to create HIBP client")
		return
	}

	for _, tc := range testTable {
		t.Run(tc.testName, func(t *testing.T) {
			breachList, _, err := hc.BreachApi.Breaches(WithDomain(tc.domain), WithoutUnverified())
			if err != nil {
				t.Error(err)
			}

			if breachList == nil && tc.isVerified && tc.isBreached {
				t.Errorf("domain %s is expected to be breached, but returned 0 results.",
					tc.domain)
			}
		})
	}
}

// TestBreachByName tests the BreachByName() method of the breaches API for a specific domain
func TestBreachByName(t *testing.T) {
	testTable := []struct {
		testName   string
		breachName string
		isBreached bool
		shouldFail bool
	}{
		{"Adobe is a known breach", "Adobe", true, false},
		{"Example is not a known breach", "Example", false, true},
	}

	hc := New()
	if hc == nil {
		t.Error("failed to create HIBP client")
		return
	}

	for _, tc := range testTable {
		t.Run(tc.testName, func(t *testing.T) {
			breachDetails, _, err := hc.BreachApi.BreachByName(tc.breachName)
			if err != nil && !tc.shouldFail {
				t.Error(err)
			}

			if breachDetails == nil && tc.isBreached {
				t.Errorf("breach with the name %q is expected to be breached, but returned 0 results.",
					tc.breachName)
			}
			if breachDetails != nil && !tc.isBreached {
				t.Errorf("breach with the name %q is expected to be not breached, but returned breach details.",
					tc.breachName)
			}
		})
	}
}
