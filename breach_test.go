package hibp

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

const (
	validDateJSON     = `{"date": "2022-10-01"}`
	validNullDateJSON = `{"date": "null"}`
	invalidJSON       = `{"date": '2022-10-01'}`
	invalidDateJSON   = `{"date": "202299-10-01"}`
)

// TestBreaches tests the Breaches() method of the breaches API
func TestBreaches(t *testing.T) {
	hc := New()
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

	hc := New(WithRateLimitSleep())
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

	hc := New(WithRateLimitSleep())
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

	hc := New(WithRateLimitSleep())
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

	apiKey := os.Getenv("HIBP_API_KEY")
	if apiKey == "" {
		t.SkipNow()
	}
	hc := New(WithApiKey(apiKey), WithRateLimitSleep())
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
		{"account-exists is breached once", "account-exists@hibp-integration-tests.com", "Adobe",
			"adobe.com", false},
		{"multiple-breaches is breached multiple times", "multiple-breaches@hibp-integration-tests.com", "Adobe",
			"adobe.com", false},
		{"opt-out is not breached", "opt-out@hibp-integration-tests.com", "", "", true},
		{"empty string should fail", "", "", "", true},
	}

	apiKey := os.Getenv("HIBP_API_KEY")
	if apiKey == "" {
		t.SkipNow()
	}
	hc := New(WithApiKey(apiKey), WithRateLimitSleep())
	for _, tc := range testTable {
		t.Run(tc.testName, func(t *testing.T) {
			breachDetails, _, err := hc.BreachApi.BreachedAccount(tc.accountName, WithoutTruncate())
			if err != nil && !tc.shouldFail {
				t.Error(err)
				return
			}
			if len(breachDetails) == 0 && !tc.shouldFail {
				t.Errorf("breach details for account %q are expected but none were returned", tc.accountName)
				return
			}

			if len(breachDetails) > 0 {
				b := breachDetails[0]
				if tc.breachName != b.Name {
					t.Errorf("breach name for the account %q does not match. expected: %q, got: %q",
						tc.accountName, tc.breachName, b.Name)
				}
				if tc.breachDomain != b.Domain {
					t.Errorf("breach domain for the account %q does not match. expected: %q, got: %q",
						tc.accountName, tc.breachDomain, b.Domain)
				}
			}
		})
	}
}

// TestApiDate_UnmarshalJSON_Time tests the ApiDate type JSON unmarshalling
func TestApiDate_UnmarshalJSON_Time(t *testing.T) {
	type testData struct {
		Date *ApiDate `json:"date"`
	}
	tt := []struct {
		n   string
		j   []byte
		d   string
		nil bool
		sf  bool
	}{
		{"valid Date JSON", []byte(validDateJSON), "2022-10-01", false, false},
		{"valid Null Date JSON", []byte(validNullDateJSON), "", true, false},
		{"invalid JSON", []byte(invalidJSON), "", true, true},
		{"invalid Date", []byte(invalidDateJSON), "", true, true},
	}

	for _, tc := range tt {
		t.Run(tc.n, func(t *testing.T) {
			var td testData
			if err := json.Unmarshal(tc.j, &td); err != nil && !tc.sf {
				t.Errorf("failed to unmarshal test JSON: %s", err)
			}
			if td.Date == nil && !tc.nil {
				t.Errorf("unmarshal on ApiDate type failed. Expected data but got nil")
				return
			}
			if !tc.nil {
				tdd := td.Date.Time().Format("2006-01-02")
				if tdd != tc.d && !tc.sf {
					t.Errorf(`unmarshal of ApiDate type failed. Expected: %q, got %q"`, tc.d, tdd)
				}
			}
		})
	}
}

// ExampleBreachApi_Breaches_getAllBreaches is a code example to show how to fetch all breaches from the
// HIBP breaches API
func ExampleBreachApi_Breaches_getAllBreaches() {
	hc := New()
	bl, _, err := hc.BreachApi.Breaches()
	if err != nil {
		panic(err)
	}
	if len(bl) != 0 {
		for _, b := range bl {
			fmt.Printf("Found breach:\n\tName: %s\n\tDomain: %s\n\tBreach date: %s\n\n",
				b.Name, b.Domain, b.BreachDate.Time().Format("Mon, 2. January 2006"))
		}
	}
}

// ExampleBreachApi_Breaches_getAllBreachesNoUnverified is a code example to show how to fetch all breaches from the
// HIBP breaches API but ignoring unverified breaches
func ExampleBreachApi_Breaches_getAllBreachesNoUnverified() {
	hc := New()
	bl, _, err := hc.BreachApi.Breaches()
	if err != nil {
		panic(err)
	}
	if len(bl) != 0 {
		fmt.Printf("Found %d breaches total.\n", len(bl))
	}

	bl, _, err = hc.BreachApi.Breaches(WithoutUnverified())
	if err != nil {
		panic(err)
	}
	if len(bl) != 0 {
		fmt.Printf("Found %d verified breaches total.\n", len(bl))
	}
}

// ExampleBreachApi_BreachByName is a code example to show how to fetch a specific breach
// from the HIBP breaches API using the BreachByName method
func ExampleBreachApi_BreachByName() {
	hc := New()
	bd, _, err := hc.BreachApi.BreachByName("Adobe")
	if err != nil {
		panic(err)
	}
	if bd != nil {
		fmt.Println("Details of the 'Adobe' breach:")
		fmt.Printf("\tDomain: %s\n", bd.Domain)
		fmt.Printf("\tBreach date: %s\n", bd.BreachDate.Time().Format("2006-01-02"))
		fmt.Printf("\tAdded to HIBP: %s\n", bd.AddedDate.String())
	}
}

// ExampleBreachApi_BreachedAccount is a code example to show how to fetch a list of breaches
// for a specific site/account from the HIBP breaches API using the BreachedAccount method
func ExampleBreachApi_BreachedAccount() {
	apiKey := os.Getenv("HIBP_API_KEY")
	if apiKey == "" {
		panic("A API key is required for this API")
	}
	hc := New(WithApiKey(apiKey))
	bd, _, err := hc.BreachApi.BreachedAccount("multiple-breaches@hibp-integration-tests.com")
	if err != nil {
		panic(err)
	}
	for _, b := range bd {
		fmt.Printf("Your account was part of the %q breach\n", b.Name)
	}
}
