// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev> et al
//
// SPDX-License-Identifier: MIT

package hibp

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	validDateJSON     = `{"date": "2022-10-01"}`
	validNullDateJSON = `{"date": "null"}`
	invalidJSON       = `{"date": '2022-10-01'}`
	invalidDateJSON   = `{"date": "202299-10-01"}`

	// ServerResponseBreachesAllTruncatedUnverified represents the file path to a test dataset of all
	// truncated unverified breaches.
	ServerResponseBreachesAllTruncatedUnverified = "testdata/breach-all-truncated-unverified.txt"

	// ServerResponseBreachesAllNonTruncatedUnverified represents the file path to a test dataset of all
	// non-truncated unverified breaches.
	ServerResponseBreachesAllNonTruncatedUnverified = "testdata/breach-all-notruncate-unverified.txt"

	// ServerResponseBreachesAllNonTruncatedVerifiedOnly represents the file path to a test dataset of all
	// non-truncated verified breaches.
	ServerResponseBreachesAllNonTruncatedVerifiedOnly = "testdata/breach-all-notruncate-verifiedonly.txt"

	// ServerResponseBreachesAllTruncatedVerifiedOnly represents the file path to a test dataset of all
	// truncated verified breaches.
	ServerResponseBreachesAllTruncatedVerifiedOnly = "testdata/breach-all-truncated-verifiedonly.txt"

	// ServerResponseBreachesBrokenJSON represents the file path to a test dataset with broken or invalid
	// JSON data.
	ServerResponseBreachesBrokenJSON = "testdata/breach-broken-json.txt"

	// ServerResponseBreachesDomainTruncatedUnverified represents a file path template for truncated unverified
	// domain breach data.
	ServerResponseBreachesDomainTruncatedUnverified = "testdata/breachdomain-%s-truncated-unverified.txt"

	// ServerResponseBreachesDomainNonTruncatedUnverified represents the path for a non-truncated, unverified
	// domain breach file.
	ServerResponseBreachesDomainNonTruncatedUnverified = "testdata/breachdomain-%s-notruncate-unverified.txt"

	// ServerResponseBreachesDomainNonTruncatedVerifiedOnly represents a file path for non-truncated, verified-only
	// breach data by domain.
	ServerResponseBreachesDomainNonTruncatedVerifiedOnly = "testdata/breachdomain-%s-notruncate-verifiedonly.txt"

	// ServerResponseBreachesDomainTruncatedVerifiedOnly represents the file path for a specific truncated,
	// verified-only breach response.
	ServerResponseBreachesDomainTruncatedVerifiedOnly = "testdata/breachdomain-%s-truncated-verifiedonly.txt"

	// ServerResponseBreachByName represents the file path format for breach data identified by name
	ServerResponseBreachByName = "testdata/breachbyname-%s.txt"

	// ServerResponseBreachLatestBreach is the file path containing the test data for the latest breach response.
	ServerResponseBreachLatestBreach = "testdata/breach-latestbreach.txt"

	// ServerResponseBreachLatestBreachBroken represents the path to a test file containing broken data for the
	// latest breach endpoint.
	ServerResponseBreachLatestBreachBroken = "testdata/breach-latestbreach-broken.txt"
)

func TestBreachAPI_Breaches(t *testing.T) {
	t.Run("return all breaches, truncated, including unverified", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseBreachesAllTruncatedUnverified))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		breaches, _, err := hc.BreachAPI.Breaches()
		if err != nil {
			t.Errorf("failed to get breaches: %s", err)
		}
		if len(breaches) != 871 {
			t.Errorf("expected 871 breaches, got %d", len(breaches))
		}
	})
	t.Run("return all breaches, truncated, including unverified, nil options", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseBreachesAllTruncatedUnverified))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		breaches, _, err := hc.BreachAPI.Breaches(nil)
		if err != nil {
			t.Errorf("failed to get breaches: %s", err)
		}
		if len(breaches) != 871 {
			t.Errorf("expected 871 breaches, got %d", len(breaches))
		}
	})
	t.Run("return all breaches, non-truncated, including unverified", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseBreachesAllNonTruncatedUnverified))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		breaches, _, err := hc.BreachAPI.Breaches(WithoutTruncate())
		if err != nil {
			t.Errorf("failed to get breaches: %s", err)
		}
		if len(breaches) != 871 {
			t.Errorf("expected 871 breaches, got %d", len(breaches))
		}
	})
	t.Run("return all breaches, non-truncated, exclude unverified", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseBreachesAllNonTruncatedVerifiedOnly))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		breaches, _, err := hc.BreachAPI.Breaches(WithoutTruncate(), WithoutUnverified())
		if err != nil {
			t.Errorf("failed to get breaches: %s", err)
		}
		if len(breaches) != 871 {
			t.Errorf("expected 871 breaches, got %d", len(breaches))
		}
	})
	t.Run("return all breaches, truncated, exclude unverified", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseBreachesAllTruncatedVerifiedOnly))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		breaches, _, err := hc.BreachAPI.Breaches(WithoutTruncate(), WithoutUnverified())
		if err != nil {
			t.Errorf("failed to get breaches: %s", err)
		}
		if len(breaches) != 871 {
			t.Errorf("expected 871 breaches, got %d", len(breaches))
		}
	})
	t.Run("return all breaches on broken JSON should fail", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseBreachesBrokenJSON))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.BreachAPI.Breaches()
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestBreachAPI_Breaches_using_WithDomain(t *testing.T) {
	tests := []struct {
		name     string
		breached bool
		verified bool
	}{
		{"adobe.com", true, true},
		{"parapa.mail.ru", true, true},
		{"xiaomi.cn", true, false},
		{"example.com", false, false},
	}
	for _, tt := range tests {
		t.Run("get breaches for "+tt.name+", truncated, including unverified", func(t *testing.T) {
			response := fmt.Sprintf(ServerResponseBreachesDomainTruncatedUnverified, tt.name)
			server := httptest.NewServer(newTestFileHandler(t, response))
			defer server.Close()
			hc := New(WithHTTPClient(newTestClient(t, server.URL)))
			breaches, _, err := hc.BreachAPI.Breaches(WithDomain(tt.name))
			if err != nil {
				t.Errorf("failed to get breaches: %s", err)
			}
			if tt.breached && len(breaches) == 0 {
				t.Errorf("expected breaches for domain %q, got none", tt.name)
			}
			if !tt.breached && len(breaches) > 0 {
				t.Errorf("expected no breaches for domain %q, got %d", tt.name, len(breaches))
			}
			if len(breaches) > 0 && breaches[0].Domain != tt.name {
				t.Errorf("expected breaches for domain %q, got %q", tt.name, breaches[0].Domain)
			}
		})
		t.Run("get breaches for "+tt.name+", non-truncated, including unverified", func(t *testing.T) {
			response := fmt.Sprintf(ServerResponseBreachesDomainNonTruncatedUnverified, tt.name)
			server := httptest.NewServer(newTestFileHandler(t, response))
			defer server.Close()
			hc := New(WithHTTPClient(newTestClient(t, server.URL)))
			breaches, _, err := hc.BreachAPI.Breaches(WithDomain(tt.name))
			if err != nil {
				t.Errorf("failed to get breaches: %s", err)
			}
			if tt.breached && len(breaches) == 0 {
				t.Errorf("expected breaches for domain %q, got none", tt.name)
			}
			if !tt.breached && len(breaches) > 0 {
				t.Errorf("expected no breaches for domain %q, got %d", tt.name, len(breaches))
			}
			if len(breaches) > 0 && breaches[0].Domain != tt.name {
				t.Errorf("expected breaches for domain %q, got %q", tt.name, breaches[0].Domain)
			}
		})
		t.Run("get breaches for "+tt.name+", non-truncated, excluding unverified", func(t *testing.T) {
			response := fmt.Sprintf(ServerResponseBreachesDomainNonTruncatedVerifiedOnly, tt.name)
			server := httptest.NewServer(newTestFileHandler(t, response))
			defer server.Close()
			hc := New(WithHTTPClient(newTestClient(t, server.URL)))
			breaches, _, err := hc.BreachAPI.Breaches(WithDomain(tt.name))
			if err != nil {
				t.Errorf("failed to get breaches: %s", err)
			}
			if tt.breached && tt.verified && len(breaches) == 0 {
				t.Errorf("expected breaches for domain %q, got none", tt.name)
			}
			if !tt.breached && len(breaches) > 0 {
				t.Errorf("expected no breaches for domain %q, got %d", tt.name, len(breaches))
			}
			if len(breaches) > 0 && breaches[0].Domain != tt.name {
				t.Errorf("expected breaches for domain %q, got %q", tt.name, breaches[0].Domain)
			}
		})
		t.Run("get breaches for "+tt.name+", truncated, excluding unverified", func(t *testing.T) {
			response := fmt.Sprintf(ServerResponseBreachesDomainTruncatedVerifiedOnly, tt.name)
			server := httptest.NewServer(newTestFileHandler(t, response))
			defer server.Close()
			hc := New(WithHTTPClient(newTestClient(t, server.URL)))
			breaches, _, err := hc.BreachAPI.Breaches(WithDomain(tt.name))
			if err != nil {
				t.Errorf("failed to get breaches: %s", err)
			}
			if tt.breached && tt.verified && len(breaches) == 0 {
				t.Errorf("expected breaches for domain %q, got none", tt.name)
			}
			if !tt.breached && len(breaches) > 0 {
				t.Errorf("expected no breaches for domain %q, got %d", tt.name, len(breaches))
			}
			if len(breaches) > 0 && breaches[0].Domain != tt.name {
				t.Errorf("expected breaches for domain %q, got %q", tt.name, breaches[0].Domain)
			}
		})
	}
}

func TestBreachAPI_BreachByName(t *testing.T) {
	tests := []struct {
		name     string
		verified bool
	}{
		{"Adobe", true},
		{"Parapa", true},
		{"Xiaomi", false},
	}
	for _, tt := range tests {
		t.Run("get breach by name for "+tt.name, func(t *testing.T) {
			response := fmt.Sprintf(ServerResponseBreachByName, strings.ToLower(tt.name))
			server := httptest.NewServer(newTestFileHandler(t, response))
			defer server.Close()
			hc := New(WithHTTPClient(newTestClient(t, server.URL)))
			breach, _, err := hc.BreachAPI.BreachByName(tt.name)
			if err != nil {
				t.Errorf("failed to get breach: %s", err)
			}
			if breach.Name != tt.name {
				t.Errorf("expected breach for name %q, got %q", tt.name, breach.Name)
			}
			if tt.verified && breach.IsVerified == false {
				t.Errorf("expected breach for name %q to be verified, got %t", tt.name, breach.IsVerified)
			}
		})
	}
	t.Run("get breach with empty name should fail", func(t *testing.T) {
		response := fmt.Sprintf(ServerResponseBreachByName, "adobe")
		server := httptest.NewServer(newTestFileHandler(t, response))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.BreachAPI.BreachByName("")
		if err == nil {
			t.Errorf("expected to fail with empty name")
		}
		if !errors.Is(err, ErrNoName) {
			t.Errorf("expected to error to be: %s, got: %s", ErrNoName, err)
		}
	})
	t.Run("get breach should fail on HTTP error", func(t *testing.T) {
		server := httptest.NewServer(newTestFailureHandler(t, http.StatusInternalServerError))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.BreachAPI.BreachByName("Adobe")
		if err == nil {
			t.Errorf("expected to fail on HTTP error")
		}
	})
	t.Run("get breach with broken JSON should fail", func(t *testing.T) {
		response := fmt.Sprintf(ServerResponseBreachByName, "brokenjson")
		server := httptest.NewServer(newTestFileHandler(t, response))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.BreachAPI.BreachByName("brokenjson")
		if err == nil {
			t.Errorf("expected to fail with empty name")
		}
	})
}

func TestBreachAPI_LatestBreach(t *testing.T) {
	t.Run("get latest breach", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseBreachLatestBreach))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		breach, _, err := hc.BreachAPI.LatestBreach()
		if err != nil {
			t.Errorf("failed to get latest breach: %s", err)
		}
		if breach.Name != "AlienStealerLogs" {
			t.Errorf("expected latest breach to be AlienStealerLogs, got %s", breach.Name)
		}
		if !breach.IsVerified {
			t.Errorf("expected latest breach to be verified, got %t", breach.IsVerified)
		}
	})
	t.Run("get latest breach should fail on HTTP error", func(t *testing.T) {
		server := httptest.NewServer(newTestFailureHandler(t, http.StatusInternalServerError))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.BreachAPI.LatestBreach()
		if err == nil {
			t.Errorf("expected to fail on HTTP error")
		}
	})
	t.Run("get latest breach with broken JSON should fail", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseBreachLatestBreachBroken))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.BreachAPI.LatestBreach()
		if err == nil {
			t.Errorf("expected to fail with empty name")
		}
	})
}

/*

// TestBreachAPI_Breaches_WithDomain tests the Breaches() method of the breaches API for a specific domain
func TestBreachAPI_Breaches_WithDomain(t *testing.T) {
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
			breachList, _, err := hc.BreachAPI.Breaches(WithDomain(tc.domain))
			if err != nil {
				t.Error(err)
				return
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

// TestBreachAPI_Breaches_WithoutUnverified tests the Breaches() method of the breaches API with the unverified parameter
func TestBreachAPI_Breaches_WithoutUnverified(t *testing.T) {
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
			breachList, _, err := hc.BreachAPI.Breaches(WithDomain(tc.domain), WithoutUnverified())
			if err != nil {
				t.Error(err)
				return
			}

			if breachList == nil && tc.isVerified && tc.isBreached {
				t.Errorf("domain %s is expected to be breached, but returned 0 results.",
					tc.domain)
			}
		})
	}
}

// TestBreachAPI_BreachByName tests the BreachByName() method of the breaches API for a specific domain
func TestBreachAPI_BreachByName(t *testing.T) {
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
			breachDetails, _, err := hc.BreachAPI.BreachByName(tc.breachName)
			if err != nil && !tc.shouldFail {
				t.Error(err)
				return
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

// TestBreachAPI_BreachByName_FailedHTTP tests the BreachByName() method with a failing HTTP request
func TestBreachAPI_BreachByName_FailedHTTP(t *testing.T) {
	hc := New(WithRateLimitSleep())
	_, res, err := hc.BreachAPI.BreachByName("fäiled_invalid")
	if err == nil {
		t.Errorf("HTTP request was supposed to fail but didn't")
	}
	if res == nil {
		t.Errorf("expected HTTP response but got nil")
	}
}

// TestBreachAPI_BreachByName_Errors tests the errors for the BreachByName() method
func TestBreachAPI_BreachByName_Errors(t *testing.T) {
	hc := New(WithRateLimitSleep())
	_, _, err := hc.BreachAPI.BreachByName("")
	if !errors.Is(err, ErrNoName) {
		t.Errorf("expected to receive ErrNoName error but didn't")
	}
}

// TestBreachAPI_LatestBreach tests the LatestBreach method of the breaches API
func TestBreachAPI_LatestBreach(t *testing.T) {
	hc := New()
	breach, _, err := hc.BreachAPI.LatestBreach()
	if err != nil {
		t.Error(err)
		return
	}

	if breach == nil {
		t.Error("No breach returned")
	}
}

// TestBreachAPI_DataClasses tests the DataClasses() method of the breaches API
func TestBreachAPI_DataClasses(t *testing.T) {
	hc := New()
	classList, _, err := hc.BreachAPI.DataClasses()
	if err != nil {
		t.Error(err)
		return
	}
	if classList != nil && len(classList) <= 0 {
		t.Error("breaches list returned 0 results")
	}
}

// TestBreachAPI_BreachedAccount tests the BreachedAccount() method of the breaches API
func TestBreachAPI_BreachedAccount(t *testing.T) {
	testTable := []struct {
		testName          string
		accountName       string
		isBreached        bool
		moreThanOneBreach bool
	}{
		{
			"account-exists is breached once", "account-exists", true,
			false,
		},
		{
			"multiple-breaches is breached multiple times", "multiple-breaches",
			true, true,
		},
		{"opt-out is not breached", "opt-out", false, false},
	}

	apiKey := os.Getenv("HIBP_API_KEY")
	if apiKey == "" {
		t.SkipNow()
	}
	hc := New(WithAPIKey(apiKey), WithRateLimitSleep())
	for _, tc := range testTable {
		t.Run(tc.testName, func(t *testing.T) {
			breachDetails, _, err := hc.BreachAPI.BreachedAccount(
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

// TestBreachAPI_BreachedAccount_FailedHTTP tests the BreachedAccount() method of the breaches API with a failing
// HTTP request
func TestBreachAPI_BreachedAccount_FailedHTTP(t *testing.T) {
	apiKey := os.Getenv("HIBP_API_KEY")
	if apiKey == "" {
		t.SkipNow()
	}
	hc := New(WithAPIKey(apiKey), WithRateLimitSleep())
	_, res, err := hc.BreachAPI.BreachedAccount("bröken@invalid_domain.tld")
	if err == nil {
		t.Error("HTTP request was supposed to fail, but didn't")
	}
	if res == nil {
		t.Errorf("expected HTTP response but got nil")
	}
}

// TestBreachAPI_BreachedAccount_Errors tests the errors for the BreachedAccount() method
func TestBreachAPI_BreachedAccount_Errors(t *testing.T) {
	hc := New(WithRateLimitSleep())
	_, _, err := hc.BreachAPI.BreachedAccount("")
	if !errors.Is(err, ErrNoAccountID) {
		t.Errorf("expected to receive ErrNoAccountID error but didn't")
	}
}

// TestBreachAPI_BreachedAccount_WithoutTruncate tests the BreachedAccount() method of the breaches API with the
// truncateResponse option set to false
func TestBreachAPI_BreachedAccount_WithoutTruncate(t *testing.T) {
	testTable := []struct {
		testName     string
		accountName  string
		breachName   string
		breachDomain string
		shouldFail   bool
	}{
		{
			"account-exists is breached once", "account-exists@hibp-integration-tests.com",
			"Adobe", "adobe.com", false,
		},
		{
			"multiple-breaches is breached multiple times", "multiple-breaches@hibp-integration-tests.com",
			"Adobe", "adobe.com", false,
		},
		{
			"opt-out is not breached", "opt-out@hibp-integration-tests.com", "",
			"", true,
		},
		{"empty string should fail", "", "", "", true},
	}

	apiKey := os.Getenv("HIBP_API_KEY")
	if apiKey == "" {
		t.SkipNow()
	}
	hc := New(WithAPIKey(apiKey), WithRateLimitSleep())
	for _, tc := range testTable {
		t.Run(tc.testName, func(t *testing.T) {
			breachDetails, _, err := hc.BreachAPI.BreachedAccount(tc.accountName, WithoutTruncate())
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

// TestBreachAPI_SubscribedDomains tests the SubscribedDomains() method of the breaches API
func TestBreachAPI_SubscribedDomains(t *testing.T) {
	apiKey := os.Getenv("HIBP_API_KEY")
	if apiKey == "" {
		t.SkipNow()
	}
	hc := New(WithAPIKey(apiKey), WithRateLimitSleep())

	domains, _, err := hc.BreachAPI.SubscribedDomains()
	if err != nil {
		t.Error(err)
	}

	if len(domains) < 1 {
		t.Log("no subscribed domains found with provided api key")
		t.SkipNow()
	}

	for i, domain := range domains {
		t.Run(fmt.Sprintf("checking domain %d", i), func(t *testing.T) {
			if domain.DomainName == "" {
				t.Error("domain name is missing")
			}

			if domain.NextSubscriptionRenewal.Time().IsZero() {
				t.Error("next subscription renewal is missing")
			}
		})
	}
}

// TestBreachAPI_BreachedDomain tests the BreachedDomain() method of the breaches API
func TestBreachAPI_BreachedDomain(t *testing.T) {
	apiKey := os.Getenv("HIBP_API_KEY")
	if apiKey == "" {
		t.SkipNow()
	}
	hc := New(WithAPIKey(apiKey), WithRateLimitSleep())

	domains, _, err := hc.BreachAPI.SubscribedDomains()
	if err != nil {
		t.Error(err)
	}

	if len(domains) < 1 {
		t.Log("no subscribed domains found with provided api key")
		t.SkipNow()
	}

	for i, domain := range domains {
		t.Run(fmt.Sprintf("checking domain %d", i), func(t *testing.T) {
			breaches, _, err := hc.BreachAPI.BreachedDomain(domain.DomainName)
			if err != nil {
				t.Error(err)
			}

			if len(breaches) < 1 {
				t.Logf("domain %s contains no breaches", domain.DomainName)
				t.SkipNow()
			}

			for alias, list := range breaches {
				if l := len(list); l == 0 {
					t.Errorf("alias %s contains %d breaches, there should be at least 1", alias, l)
				}
			}
		})
	}
}

// TestAPIDate_UnmarshalJSON_Time tests the APIDate type JSON unmarshalling
func TestAPIDate_UnmarshalJSON_Time(t *testing.T) {
	type testData struct {
		Date *APIDate `json:"date"`
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
				t.Errorf("unmarshal on APIDate type failed. Expected data but got nil")
				return
			}
			if !tc.nil {
				tdd := td.Date.Time().Format("2006-01-02")
				if tdd != tc.d && !tc.sf {
					t.Errorf(`unmarshal of APIDate type failed. Expected: %q, got %q"`, tc.d, tdd)
				}
			}
		})
	}
}

// ExampleBreachAPI_Breaches_getAllBreaches is a code example to show how to fetch all breaches from the
// HIBP breaches API
func ExampleBreachAPI_Breaches_getAllBreaches() {
	hc := New()
	bl, _, err := hc.BreachAPI.Breaches()
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

// ExampleBreachAPI_Breaches_getAllBreachesNoUnverified is a code example to show how to fetch all breaches from the
// HIBP breaches API but ignoring unverified breaches
func ExampleBreachAPI_Breaches_getAllBreachesNoUnverified() {
	hc := New()
	bl, _, err := hc.BreachAPI.Breaches()
	if err != nil {
		panic(err)
	}
	if len(bl) != 0 {
		fmt.Printf("Found %d breaches total.\n", len(bl))
	}

	bl, _, err = hc.BreachAPI.Breaches(WithoutUnverified())
	if err != nil {
		panic(err)
	}
	if len(bl) != 0 {
		fmt.Printf("Found %d verified breaches total.\n", len(bl))
	}
}

// ExampleBreachAPI_BreachByName is a code example to show how to fetch a specific breach
// from the HIBP breaches API using the BreachByName method
func ExampleBreachAPI_BreachByName() {
	hc := New()
	bd, _, err := hc.BreachAPI.BreachByName("Adobe")
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

// ExampleBreachAPI_BreachedAccount is a code example to show how to fetch a list of breaches
// for a specific site/account from the HIBP breaches API using the BreachedAccount method
func ExampleBreachAPI_BreachedAccount() {
	apiKey := os.Getenv("HIBP_API_KEY")
	if apiKey == "" {
		panic("A API key is required for this API")
	}
	hc := New(WithAPIKey(apiKey))
	bd, _, err := hc.BreachAPI.BreachedAccount("multiple-breaches@hibp-integration-tests.com")
	if err != nil {
		panic(err)
	}
	for _, b := range bd {
		fmt.Printf("Your account was part of the %q breach\n", b.Name)
	}
}


*/
