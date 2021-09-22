package hibp

import (
	"fmt"
	"os"
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

// TestBreachesWithNil tests the Breaches() method of the breaches API with a nil option
func TestBreachesWithNil(t *testing.T) {
	hc := New()
	if hc == nil {
		t.Errorf("hibp client creation failed")
		return
	}

	breachList, _, err := hc.BreachApi.Breaches(nil)
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

// TestDataClasses tests the DataClasses() method of the breaches API
func TestDataClasses(t *testing.T) {
	hc := New()
	if hc == nil {
		t.Errorf("hibp client creation failed")
		return
	}

	classList, _, err := hc.BreachApi.DataClasses()
	if err != nil {
		t.Error(err)
	}
	if classList != nil && len(classList) <= 0 {
		t.Error("breaches list returned 0 results")
	}
}

// TestBreachedAccount tests the BreachedAccount() method of the breaches API
func TestBreachedAccount(t *testing.T) {
	testTable := []struct {
		testName          string
		accountName       string
		isBreached        bool
		moreThanOneBreach bool
	}{
		{"account-exists is breached once", "account-exists", true,
			false},
		{"multiple-breaches is breached multiple times", "multiple-breaches",
			true, true},
		{"opt-out is not breached", "opt-out", false, false},
	}

	hc := New(WithApiKey(os.Getenv("HIBP_API_KEY")))
	if hc == nil {
		t.Error("failed to create HIBP client")
		return
	}

	for _, tc := range testTable {
		t.Run(tc.testName, func(t *testing.T) {
			breachDetails, _, err := hc.BreachApi.BreachedAccount(
				fmt.Sprintf("%s@hibp-integration-tests.com", tc.accountName))
			if err != nil && tc.isBreached {
				t.Error(err)
			}

			if breachDetails == nil && tc.isBreached {
				t.Errorf("breach for the account %q is expected, but returned 0 results.",
					tc.accountName)
			}
			if breachDetails != nil && !tc.isBreached {
				t.Errorf("breach for the account %q is expected to be not breached, but returned breach details.",
					tc.accountName)
			}
			if breachDetails != nil && tc.moreThanOneBreach && len(breachDetails) <= 1 {
				t.Errorf("breach for the account %q is expected to be breached multiple, but returned %d breaches.",
					tc.accountName, len(breachDetails))
			}
			if breachDetails != nil && !tc.moreThanOneBreach && len(breachDetails) > 1 {
				t.Errorf("breach for the account %q is expected to be breached once, but returned %d breaches.",
					tc.accountName, len(breachDetails))
			}
		})
	}
}

// TestBreachedAccountWithoutTruncate tests the BreachedAccount() method of the breaches API with the
// truncateResponse option set to false
func TestBreachedAccountWithoutTruncate(t *testing.T) {
	testTable := []struct {
		testName     string
		accountName  string
		breachName   string
		breachDomain string
		shouldFail   bool
	}{
		{"account-exists is breached once", "account-exists", "Adobe",
			"adobe.com", false},
		{"multiple-breaches is breached multiple times", "multiple-breaches", "Adobe",
			"adobe.com", false},
		{"opt-out is not breached", "opt-out", "", "", true},
	}

	hc := New(WithApiKey(os.Getenv("HIBP_API_KEY")), WithRateLimitNoFail())
	if hc == nil {
		t.Error("failed to create HIBP client")
		return
	}

	for _, tc := range testTable {
		t.Run(tc.testName, func(t *testing.T) {
			breachDetails, _, err := hc.BreachApi.BreachedAccount(
				fmt.Sprintf("%s@hibp-integration-tests.com", tc.accountName),
				WithoutTruncate())
			if err != nil && !tc.shouldFail {
				t.Error(err)
				return
			}

			for _, b := range breachDetails {
				if tc.breachName != b.Name {
					t.Errorf("breach name for the account %q does not match. expected: %q, got: %q",
						tc.accountName, tc.breachName, b.Name)
				}
				if tc.breachDomain != b.Domain {
					t.Errorf("breach domain for the account %q does not match. expected: %q, got: %q",
						tc.accountName, tc.breachDomain, b.Domain)
				}
				return
			}
		})
	}
}
