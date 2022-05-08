package hibp

import (
	"fmt"
	"os"
	"testing"
)

// TestPasteAccount tests the BreachedAccount() method of the breaches API
func TestPasteAccount(t *testing.T) {
	testTable := []struct {
		testName    string
		accountName string
		isBreached  bool
		shouldFail  bool
	}{
		{"account-exists is breached once", "account-exists@hibp-integration-tests.com", true, false},
		{"opt-out is not breached", "opt-out-breach@hibp-integration-tests.com", false, true},
		{"empty account name", "", false, true},
	}

	apiKey := os.Getenv("HIBP_API_KEY")
	if apiKey == "" {
		t.SkipNow()
	}
	hc := New(WithApiKey(apiKey), WithRateLimitSleep())
	for _, tc := range testTable {
		t.Run(tc.testName, func(t *testing.T) {
			pasteDetails, _, err := hc.PasteApi.PastedAccount(tc.accountName)
			if err != nil && !tc.shouldFail {
				t.Error(err)
			}

			if pasteDetails == nil && tc.isBreached {
				t.Errorf("breach for the account %q is expected, but returned 0 results.",
					tc.accountName)
			}
			if pasteDetails != nil && !tc.isBreached {
				t.Errorf("breach for the account %q is expected to be not breached, but returned breach details.",
					tc.accountName)
			}
		})
	}
}

// ExamplePasteApi_PastedAccount is a code example to show how to fetch a specific paste
// based on its name from the HIBP pastes API using the PastedAccount() method
func ExamplePasteApi_PastedAccount() {
	apiKey := os.Getenv("HIBP_API_KEY")
	if apiKey == "" {
		panic("A API key is required for this API")
	}
	hc := New(WithApiKey(apiKey))
	pd, _, err := hc.PasteApi.PastedAccount("account-exists@hibp-integration-tests.com")
	if err != nil {
		panic(err)
	}
	for _, p := range pd {
		fmt.Printf("Your account was part of the %q paste\n", p.Title)
	}
}
