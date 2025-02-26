// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev> et al
//
// SPDX-License-Identifier: MIT

package hibp

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	// PwStringInsecure is the string representation of an insecure password
	PwStringInsecure = "test"

	// PwStringSecure is the string representation of an insecure password
	PwStringSecure = "F/0Ws#.%{Z/NVax=OU8Ajf1qTRLNS12p/?s/adX"

	// PwHashInsecure is the SHA1 checksum of an insecure password
	// Represents the string: test
	PwHashInsecure = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"

	// PwHashInsecure is the NTLM hash of an insecure password
	// Represents the string: test
	PwHashInsecureNTLM = "0cb6948805f797bf2a82807973b89537"

	// PwHashSecure is the SHA1 checksum of a secure password
	// Represents the string: F/0Ws#.%{Z/NVax=OU8Ajf1qTRLNS12p/?s/adX
	PwHashSecure = "90efc095c82eab44e882fda507cfab1a2cd31fc0"

	// PwHashSecureNTLM is the NTLM hash of a secure password
	// Represents the string: F/0Ws#.%{Z/NVax=OU8Ajf1qTRLNS12p/?s/adX
	PwHashSecureNTLM = "997f11041d9aa830842e682d1b4207df"

	ServerResponseInsecure        = "testdata/pwnedpass-insecure.txt"
	ServerResponseInvalid         = "testdata/pwnedpass-invalid.txt"
	ServerResponseInsecurePadding = "testdata/pwnedpass-insecure-padding.txt"
	ServerResponseInsecureNTLM    = "testdata/pwnedpass-insecure-ntlm.txt"
	ServerResponseSecure          = "testdata/pwnedpass-secure.txt"
	ServerResponseSecurePadding   = "testdata/pwnedpass-secure-padding.txt"
	ServerResponseSecureNTLM      = "testdata/pwnedpass-secure-ntlm.txt"
)

// TestPwnedPassAPI_CheckPassword verifies the Pwned Passwords API with the CheckPassword method
func TestPwnedPassAPI_CheckPassword(t *testing.T) {
	tests := []struct {
		name     string
		pwString string
		respSHA1 string
		respNTLM string
		isLeaked bool
	}{
		{
			"weak password 'test' is expected to be leaked",
			PwStringInsecure,
			ServerResponseInsecure,
			ServerResponseInsecureNTLM,
			true,
		},
		{
			"strong, unknown password is expected to be not leaked",
			PwStringSecure,
			ServerResponseSecure,
			ServerResponseSecureNTLM,
			false,
		},
	}
	t.Run("check password with SHA-1 hashes", func(t *testing.T) {
		for _, tc := range tests {
			server := httptest.NewServer(newTestFileHandler(t, tc.respSHA1))
			hc := New(WithHTTPClient(newTestClient(t, server.URL)))
			t.Run(tc.name, func(t *testing.T) {
				m, _, err := hc.PwnedPassAPI.CheckPassword(tc.pwString)
				if err != nil {
					t.Error(err)
				}
				if m == nil && tc.isLeaked {
					t.Errorf("password is expected to be leaked but 0 leaks were returned in Pwned Passwords DB")
				}
				if m != nil && m.Count > 0 && !tc.isLeaked {
					t.Errorf("password is not expected to be leaked but %d leaks were found in Pwned Passwords DB",
						m.Count)
				}
			})
			server.Close()
		}
	})
	t.Run("check password with NTLM hashes", func(t *testing.T) {
		for _, tc := range tests {
			server := httptest.NewServer(newTestFileHandler(t, tc.respNTLM))
			hc := New(WithPwnedNTLMHash(), WithHTTPClient(newTestClient(t, server.URL)))
			t.Run(tc.name, func(t *testing.T) {
				m, _, err := hc.PwnedPassAPI.CheckPassword(tc.pwString)
				if err != nil {
					t.Error(err)
				}
				if m == nil && tc.isLeaked {
					t.Errorf("password is expected to be leaked but 0 leaks were returned in Pwned Passwords DB")
				}
				if m != nil && m.Count > 0 && !tc.isLeaked {
					t.Errorf("password is not expected to be leaked but %d leaks were found in Pwned Passwords DB",
						m.Count)
				}
			})
			server.Close()
		}
	})
	t.Run("check password fails with wrong hash mode", func(t *testing.T) {
		hc := New(WithHTTPClient(newTestClient(t, "")))
		hc.PwnedPassAPIOpts.HashMode = 99
		_, _, err := hc.PwnedPassAPI.CheckPassword(PwStringInsecure)
		if err == nil {
			t.Error("CheckPassword with unsupported HashMode was supposed to fail, but didn't")
		}
		if !errors.Is(err, ErrUnsupportedHashMode) {
			t.Errorf("CheckPassword wrong error, expected: %s, got: %s", ErrUnsupportedHashMode, err)
		}
	})
}

func TestPwnedPassAPI_CheckSHA1(t *testing.T) {
	t.Run("CheckSHA1 with invalid length hash should fail", func(t *testing.T) {
		hc := New()
		_, _, err := hc.PwnedPassAPI.CheckSHA1("123456abcdef")
		if err == nil {
			t.Errorf("CheckSHA1 with invalid length hash should fail")
		}
	})
	t.Run("CheckSHA1 with invalid URL should fail", func(t *testing.T) {
		hc := New(WithHTTPClient(newTestClient(t, "")))
		_, _, err := hc.PwnedPassAPI.CheckSHA1(PwHashInsecure)
		if err == nil {
			t.Errorf("CheckSHA1 with invalid URL should fail")
		}
	})
}

func TestPwnedPassAPI_CheckNTLM(t *testing.T) {
	t.Run("CheckNTLM with invalid length hash should fail", func(t *testing.T) {
		hc := New()
		_, _, err := hc.PwnedPassAPI.CheckNTLM("123456abcdef")
		if err == nil {
			t.Errorf("CheckNTLM with invalid length hash should fail")
		}
	})
	t.Run("CheckNTLM with invalid URL should fail", func(t *testing.T) {
		hc := New(WithHTTPClient(newTestClient(t, "")))
		_, _, err := hc.PwnedPassAPI.CheckNTLM(PwHashInsecureNTLM)
		if err == nil {
			t.Errorf("CheckNTLM with invalid URL should fail")
		}
	})
}

func TestPwnedPassAPI_ListHashesPassword(t *testing.T) {
	t.Run("ListHashesPassword in SHA-1 mode succeeds on leaked password", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseInsecure))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		m, _, err := hc.PwnedPassAPI.ListHashesPassword("test")
		if err != nil {
			t.Fatalf("ListHashesPassword was not supposed to fail, but did: %s", err)
		}
		if len(m) != 987 {
			t.Errorf("ListHashesPassword was supposed to return 987 results, but got %d", len(m))
		}
	})
	t.Run("ListHashesPassword in NTLM mode succeeds on leaked password", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseInsecureNTLM))
		defer server.Close()
		hc := New(WithPwnedNTLMHash(), WithHTTPClient(newTestClient(t, server.URL)))
		m, _, err := hc.PwnedPassAPI.ListHashesPassword("test")
		if err != nil {
			t.Fatalf("ListHashesPassword was not supposed to fail, but did: %s", err)
		}
		if len(m) != 978 {
			t.Errorf("ListHashesPassword was supposed to return 978 results, but got %d", len(m))
		}
	})
	t.Run("ListHashesPassword in SHA-1 mode succeeds on leaked passwords and padding enabled", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseInsecurePadding))
		defer server.Close()
		hc := New(WithPwnedPadding(), WithHTTPClient(newTestClient(t, server.URL)))
		m, _, err := hc.PwnedPassAPI.ListHashesPassword("test")
		if err != nil {
			t.Fatalf("ListHashesPassword was not supposed to fail, but did: %s", err)
		}
		if len(m) != 987 {
			t.Errorf("ListHashesPassword was supposed to return 987 results, but got %d", len(m))
		}
	})
	t.Run("ListHashesPassword with invalid hash mode should fail", func(t *testing.T) {
		hc := New()
		hc.PwnedPassAPIOpts.HashMode = 99
		_, _, err := hc.PwnedPassAPI.ListHashesPassword("test")
		if err == nil {
			t.Errorf("ListHashesPassword with unsupported hash mode was supposed to fail")
		}
		if !errors.Is(err, ErrUnsupportedHashMode) {
			t.Errorf("ListHashesPassword wrong error, expected: %s, got: %s", ErrUnsupportedHashMode, err)
		}
	})
}

func TestPwnedPassAPI_ListHashesSHA1(t *testing.T) {
	t.Run("ListHashesSHA1 fails with too short hash", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseInsecure))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.PwnedPassAPI.ListHashesSHA1("1234567890abcdef")
		if err == nil {
			t.Errorf("ListHashesSHA1 with too short hash should fail")
		}
		if !errors.Is(err, ErrSHA1LengthMismatch) {
			t.Errorf("ListHashesSHA1 wrong error, expected: %s, got: %s", ErrSHA1LengthMismatch, err)
		}
	})
	t.Run("ListHashesSHA1 fails with invalid hash", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseInsecure))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.PwnedPassAPI.ListHashesSHA1(PwHashInsecure[:39] + "h")
		if err == nil {
			t.Errorf("ListHashesSHA1 with invalid hash should fail")
		}
		if !errors.Is(err, ErrSHA1Invalid) {
			t.Errorf("ListHashesSHA1 wrong error, expected: %s, got: %s", ErrSHA1Invalid, err)
		}
	})
}

func TestPwnedPassAPI_ListHashesNTLM(t *testing.T) {
	t.Run("ListHashesNTLM fails with too short hash", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseInsecureNTLM))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.PwnedPassAPI.ListHashesNTLM("1234567890abcdef")
		if err == nil {
			t.Errorf("ListHashesNTLM with too short hash should fail")
		}
		if !errors.Is(err, ErrNTLMLengthMismatch) {
			t.Errorf("ListHashesNTLM wrong error, expected: %s, got: %s", ErrNTLMLengthMismatch, err)
		}
	})
	t.Run("ListHashesNTLM fails with invalid hash", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseInsecure))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.PwnedPassAPI.ListHashesNTLM(PwHashInsecure[:31] + "h")
		if err == nil {
			t.Errorf("ListHashesNTLM with invalid hash should fail")
		}
		if !errors.Is(err, ErrNTLMInvalid) {
			t.Errorf("ListHashesNTLM wrong error, expected: %s, got: %s", ErrNTLMInvalid, err)
		}
	})
}

func TestPwnedPassAPI_ListHashesPrefix(t *testing.T) {
	t.Run("ListHashesPrefix fails with too short prefix", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseInsecureNTLM))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.PwnedPassAPI.ListHashesPrefix("123")
		if err == nil {
			t.Errorf("ListHashesPrefix with too short hash should fail")
		}
		if !errors.Is(err, ErrPrefixLengthMismatch) {
			t.Errorf("ListHashesPrefix wrong error, expected: %s, got: %s", ErrPrefixLengthMismatch, err)
		}
	})
	t.Run("ListHashesPrefix with unsupported hash mode should fallback to default", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseInsecure))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		hc.PwnedPassAPIOpts.HashMode = 99
		_, _, err := hc.PwnedPassAPI.ListHashesPrefix("a94a8")
		if err != nil {
			t.Errorf("ListHashesPrefix with unsupported hash mode failed: %s", err)
		}
	})
	t.Run("ListHashesPrefix fails on HTTP request", func(t *testing.T) {
		server := httptest.NewServer(newTestFailureHandler(t, http.StatusInternalServerError))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.PwnedPassAPI.ListHashesPrefix("a94a8")
		if err == nil {
			t.Error("ListHashesPrefix was supposed to fail on HTTP request")
		}
		if !errors.Is(err, ErrNonPositiveResponse) {
			t.Errorf("ListHashesPrefix wrong error, expected: %s, got: %s", ErrNonPositiveResponse, err)
		}
	})
	t.Run("ListHashesPrefix skips over invalid result lines", func(t *testing.T) {
		server := httptest.NewServer(newTestFileHandler(t, ServerResponseInvalid))
		defer server.Close()
		hc := New(WithHTTPClient(newTestClient(t, server.URL)))
		_, _, err := hc.PwnedPassAPI.ListHashesPrefix("a94a8")
		if err != nil {
			t.Errorf("ListHashesPrefix failed: %s", err)
		}
	})
}

// TestPwnedPassAPI_checkPassword_integration preforms an integration test against the
// online PwnedPass API instead of our mock server
func TestPwnedPassAPI_CheckPassword_integration(t *testing.T) {
	hc := New()
	m, _, err := hc.PwnedPassAPI.CheckPassword("test")
	if err != nil {
		t.Errorf("CheckPassword failed: %s", err)
	}
	if m.Count == 0 {
		t.Error("CheckPassword returned a zero count for a leaked password")
	}
}

// ExamplePwnedPassAPI_CheckPassword is a code example to show how to check a given password
// against the HIBP passwords API
func ExamplePwnedPassAPI_CheckPassword() {
	hc := New()
	m, _, err := hc.PwnedPassAPI.CheckPassword("test")
	if err != nil {
		panic(err)
	}
	if m != nil && m.Count != 0 {
		fmt.Printf("Your password with the hash %q was found in the pwned passwords DB\n", m.Hash)
		// Output: Your password with the hash "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" was found in the pwned passwords DB
	}
}

// ExamplePwnedPassAPI_CheckPassword_withPadding is a code example to show how to check a given password
// against the HIBP passwords API with the WithPadding() option set
func ExamplePwnedPassAPI_CheckPassword_withPadding() {
	hc := New(WithPwnedPadding())
	m, _, err := hc.PwnedPassAPI.CheckPassword("test")
	if err != nil {
		panic(err)
	}
	if m != nil && m.Count != 0 {
		fmt.Printf("Your password with the hash %q was found in the pwned passwords DB\n", m.Hash)
		// Output: Your password with the hash "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" was found in the pwned passwords DB
	}
}

// ExamplePwnedPassAPI_checkSHA1 is a code example to show how to check a given password SHA1 hash
// against the HIBP passwords API using the CheckSHA1() method
func ExamplePwnedPassAPI_checkSHA1() {
	hc := New()
	pwHash := "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" // represents the PW: "test"
	m, _, err := hc.PwnedPassAPI.CheckSHA1(pwHash)
	if err != nil {
		panic(err)
	}
	if m != nil && m.Count != 0 {
		fmt.Printf("Your password with the hash %q was found in the pwned passwords DB\n", m.Hash)
		// Output: Your password with the hash "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" was found in the pwned passwords DB
	}
}

// ExamplePwnedPassAPI_checkNTLM is a code example to show how to check a given password NTLM hash
// against the HIBP passwords API using the CheckNTLM() method
func ExamplePwnedPassAPI_checkNTLM() {
	hc := New()
	pwHash := "0cb6948805f797bf2a82807973b89537" // represents the PW: "test"
	m, _, err := hc.PwnedPassAPI.CheckNTLM(pwHash)
	if err != nil {
		panic(err)
	}
	if m != nil && m.Count != 0 {
		fmt.Printf("Your password with the hash %q was found in the pwned passwords DB\n", m.Hash)
		// Output: Your password with the hash "0cb6948805f797bf2a82807973b89537" was found in the pwned passwords DB
	}
}
