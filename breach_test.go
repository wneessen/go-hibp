// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev> et al
//
// SPDX-License-Identifier: MIT

package hibp

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const (
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

	// ServerResponseDataClasses represents the file path for mock server response data containing data classes.
	ServerResponseDataClasses = "testdata/dataclasses.txt"

	// ServerResponseDataClassesBroken represents the file path to test data simulating a broken dataclasses response.
	ServerResponseDataClassesBroken = "testdata/dataclasses-broken.txt"

	// ServerResponseBreachAccount represents the test data file path for simulating a breached account response.
	ServerResponseBreachAccount = "testdata/breachaccount-%s.txt"

	// ServerResponseBreachAccountBroken represents the file path for a broken breach account server response
	// mock data.
	ServerResponseBreachAccountBroken = "testdata/breachaccount-%s-broken.txt"

	// ServerResponseBreachSubscribedDomains represents the path to the mock data file for subscribed domains
	// breach responses.
	ServerResponseBreachSubscribedDomains = "testdata/breach-subscribeddomains.txt"

	// ServerResponseBreachSubscribedDomainsBroken represents a file path to test data for broken subscribed
	// domains breaches.
	ServerResponseBreachSubscribedDomainsBroken = "testdata/breach-subscribeddomains-broken.txt"

	// ServerResponseBreachedDomain represents the file path to mock server response data for a breached domain.
	ServerResponseBreachedDomain = "testdata/breacheddomain.txt"

	// ServerResponseBreachedDomainBroken represents the file path for a test dataset with a broken breached
	// domain response.
	ServerResponseBreachedDomainBroken = "testdata/breacheddomain-broken.txt"
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
	t.Run("return all breaches succeeds on rate limit", func(t *testing.T) {
		run := 0
		server := httptest.NewServer(newTestRetryHandler(t, &run, true))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)), WithRateLimitSleep(), WithLogger(newTestLogger(t)))
		_, _, err := hc.BreachAPI.Breaches()
		if err != nil {
			t.Errorf("failed to get breaches: %s", err)
		}
	})
	t.Run("return all breaches fails on rate limit", func(t *testing.T) {
		run := 0
		server := httptest.NewServer(newTestRetryHandler(t, &run, true))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)), WithLogger(newTestLogger(t)))
		_, hr, err := hc.BreachAPI.Breaches()
		if err == nil {
			t.Error("expected request to fail due to rate limiting")
		}
		if hr == nil {
			t.Fatal("expected HTTP response to be returned")
		}
		if hr.StatusCode != http.StatusTooManyRequests {
			t.Errorf("expected HTTP status code to be %d, got %d", http.StatusTooManyRequests, hr.StatusCode)
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
			if len(breaches) > 0 && tt.breached && !breaches[0].Present() {
				t.Errorf("expected breaches for domain %q to be returned by API, got %t", tt.name, breaches[0].Present())
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
			if len(breaches) > 0 && tt.breached && !breaches[0].Present() {
				t.Errorf("expected breaches for domain %q to be returned by API, got %t", tt.name, breaches[0].Present())
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
			if len(breaches) > 0 && tt.breached && !breaches[0].Present() {
				t.Errorf("expected breaches for domain %q to be returned by API, got %t", tt.name, breaches[0].Present())
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
			if len(breaches) > 0 && tt.breached && !breaches[0].Present() {
				t.Errorf("expected breaches for domain %q to be returned by API, got %t", tt.name, breaches[0].Present())
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
	t.Run("get breach for example.com should leave found-tag false", func(t *testing.T) {
		server := httptest.NewServer(newTestFailureHandler(t, http.StatusNotFound))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		breach, _, err := hc.BreachAPI.BreachByName("Example")
		if err == nil {
			t.Errorf("expected to fail on HTTP error")
		}
		if breach.Present() {
			t.Errorf("expected breach to not be found")
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

func TestBreachAPI_DataClasses(t *testing.T) {
	t.Run("data classes a returned successfully", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseDataClasses))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		classes, _, err := hc.BreachAPI.DataClasses()
		if err != nil {
			t.Errorf("failed to get data classes: %s", err)
		}
		if len(classes) != 148 {
			t.Errorf("expected %d data class, got %d", 148, len(classes))
		}
	})
	t.Run("data classes should fail on HTTP error", func(t *testing.T) {
		server := httptest.NewServer(newTestFailureHandler(t, http.StatusInternalServerError))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.BreachAPI.DataClasses()
		if err == nil {
			t.Errorf("expected to fail on HTTP error")
		}
	})
	t.Run("data classes with broken JSON should fail", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseDataClassesBroken))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.BreachAPI.DataClasses()
		if err == nil {
			t.Errorf("expected to fail on broken JSON")
		}
	})
}

func TestBreachAPI_BreachedAccount(t *testing.T) {
	apiKey := os.Getenv("HIBP_API_KEY")
	if apiKey == "" {
		t.SkipNow()
	}
	t.Run("breached account successfully returns data", func(t *testing.T) {
		email := "toni.tester@domain.tld"
		resp := fmt.Sprintf(ServerResponseBreachAccount, email)
		server := httptest.NewServer(newTestFileHandler(t, resp))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		breaches, _, err := hc.BreachAPI.BreachedAccount("toni.tester@domain.tld")
		if err != nil {
			t.Errorf("failed to get breached account: %s", err)
		}
		if len(breaches) != 5 {
			t.Errorf("expected %d breaches, got %d", 5, len(breaches))
		}
	})
	t.Run("breached account with empty account id should fail", func(t *testing.T) {
		email := "toni.tester@domain.tld"
		resp := fmt.Sprintf(ServerResponseBreachAccount, email)
		server := httptest.NewServer(newTestFileHandler(t, resp))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.BreachAPI.BreachedAccount("")
		if err == nil {
			t.Error("expected to fail with empty account id")
		}
		if !errors.Is(err, ErrNoAccountID) {
			t.Errorf("expected to error to be: %s, got: %s", ErrNoAccountID, err)
		}
	})
	t.Run("account request with no findings empty breaches list", func(t *testing.T) {
		server := httptest.NewServer(newTestFailureHandler(t, http.StatusNotFound))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		breach, _, err := hc.BreachAPI.BreachedAccount("does.not.exist@domain.tld")
		if err != nil {
			t.Errorf("failed to get breached account: %s", err)
		}
		if len(breach) != 0 {
			t.Errorf("expected %d breaches, got %d", 0, len(breach))
		}
	})
	t.Run("account request fails on HTTP error", func(t *testing.T) {
		server := httptest.NewServer(newTestFailureHandler(t, http.StatusInternalServerError))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.BreachAPI.BreachedAccount("does.not.exist@domain.tld")
		if err == nil {
			t.Error("expected to fail on HTTP error")
		}
	})
	t.Run("account request fails on broken JSON", func(t *testing.T) {
		email := "toni.tester@domain.tld"
		resp := fmt.Sprintf(ServerResponseBreachAccountBroken, email)
		server := httptest.NewServer(newTestFileHandler(t, resp))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.BreachAPI.BreachedAccount("does.not.exist@domain.tld")
		if err == nil {
			t.Error("expected to fail on broken JSON")
		}
	})
}

func TestBreachAPI_SubscribedDomains(t *testing.T) {
	t.Run("subscribed domains successfully returns data", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseBreachSubscribedDomains))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		domains, _, err := hc.BreachAPI.SubscribedDomains()
		if err != nil {
			t.Errorf("failed to get subscribed domains: %s", err)
		}
		if len(domains) != 1 {
			t.Errorf("expected %d subscribed domains, got %d", 1, len(domains))
		}
		domain := domains[0]
		if domain.PwnCount.IsNil() {
			t.Errorf("expected pwn count to be set, got nil")
		}
		if domain.PwnCountExcludingSpamLists.NotNil() {
			t.Errorf("expected pwn count excluding spam lists to be nil, got %d",
				domain.PwnCountExcludingSpamLists.Value())
		}
		if domain.PwnCountExcludingSpamListsAtLastSubscriptionRenewal.IsNil() {
			t.Errorf("expected pwn count excluding spam lists at last subscription renewal to be set, got nil")
		}
	})
	t.Run("subscribed domains should fail on HTTP error", func(t *testing.T) {
		server := httptest.NewServer(newTestFailureHandler(t, http.StatusInternalServerError))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.BreachAPI.SubscribedDomains()
		if err == nil {
			t.Errorf("expected to fail on HTTP error")
		}
	})
	t.Run("subscribed domains with broken JSON should fail", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseBreachSubscribedDomainsBroken))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.BreachAPI.SubscribedDomains()
		if err == nil {
			t.Errorf("expected to fail on broken JSON")
		}
	})
}

func TestBreachAPI_BreachedDomain(t *testing.T) {
	t.Run("breached domain successfully returns data", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseBreachedDomain))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		accounts, _, err := hc.BreachAPI.BreachedDomain("domain.tld")
		if err != nil {
			t.Errorf("failed to get breached domains %s", err)
		}
		if len(accounts) != 6 {
			t.Errorf("expected %d breached accounts, got %d", 6, len(accounts))
		}
	})
	t.Run("breached domain with no breaches returns empty list", func(t *testing.T) {
		server := httptest.NewServer(newTestFailureHandler(t, http.StatusNotFound))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		accounts, _, err := hc.BreachAPI.BreachedDomain("domain.tld")
		if err != nil {
			t.Errorf("failed to get breached domains %s", err)
		}
		if len(accounts) != 0 {
			t.Errorf("expected %d breached accounts, got %d", 0, len(accounts))
		}
	})
	t.Run("breached domain with HTTP error should fail", func(t *testing.T) {
		server := httptest.NewServer(newTestFailureHandler(t, http.StatusInternalServerError))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.BreachAPI.BreachedDomain("domain.tld")
		if err == nil {
			t.Errorf("expected to fail on HTTP error")
		}
	})
	t.Run("breached domain with broken JSON should fail", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseBreachedDomainBroken))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.BreachAPI.BreachedDomain("domain.tld")
		if err == nil {
			t.Errorf("expected to fail on broken JSON")
		}
	})
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
				b.Name, b.Domain, b.BreachDate.Format("Mon, 2. January 2006"))
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
	if bd.Present() {
		fmt.Println("Details of the 'Adobe' breach:")
		fmt.Printf("\tDomain: %s\n", bd.Domain)
		fmt.Printf("\tBreach date: %s\n", bd.BreachDate.Format("2006-01-02"))
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
