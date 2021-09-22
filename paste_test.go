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
	}{
		{"account-exists is breached once", "account-exists", true},
		{"opt-out is not breached", "opt-out", false},
	}

	apiKey := os.Getenv("HIBP_API_KEY")
	if apiKey == "" {
		t.SkipNow()
	}
	hc := New(WithApiKey(apiKey))
	for _, tc := range testTable {
		t.Run(tc.testName, func(t *testing.T) {
			pasteDetails, _, err := hc.PasteApi.PastedAccount(
				fmt.Sprintf("%s@hibp-integration-tests.com", tc.accountName))
			if err != nil && tc.isBreached {
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
