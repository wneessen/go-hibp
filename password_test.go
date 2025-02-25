// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev> et al
//
// SPDX-License-Identifier: MIT

package hibp

import (
	"errors"
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
		hc := New(WithPwnedPadding(), WithHTTPClient(newTestClient(t, server.URL)))
		m, _, err := hc.PwnedPassAPI.ListHashesPassword("test")
		if err != nil {
			t.Fatalf("ListHashesPassword was not supposed to fail, but did: %s", err)
		}
		if len(m) != 987 {
			t.Errorf("ListHashesPassword was supposed to return 987 results, but got %d", len(m))
		}
	})
}

/*
// TestPwnedPassAPI_ListHashesPrefix tests the ListHashesPrefix method (especially for failures that are not
// tested by the other tests already)
func TestPwnedPassAPI_ListHashesPrefix(t *testing.T) {
	hc := New()

	// Should return at least 1 restults
	l, _, err := hc.PwnedPassAPI.ListHashesPrefix("a94a8")
	if err != nil {
		t.Errorf("ListHashesPrefix was not supposed to fail, but did: %s", err)
	}
	if len(l) <= 0 {
		t.Errorf("ListHashesPrefix was supposed to return a list longer than 0")
	}

	// Prefix has wrong size
	_, _, err = hc.PwnedPassAPI.ListHashesPrefix("ZZZZZZZZZZZZZZ")
	if err == nil {
		t.Errorf("ListHashesPrefix was supposed to fail, but didn't")
	}

	// Non allowed characters
	_, _, err = hc.PwnedPassAPI.ListHashesPrefix(string([]byte{0, 0, 0, 0, 0}))
	if err == nil {
		t.Errorf("ListHashesPrefix was supposed to fail, but didn't")
	}

	// Should fall back to SHA-1
	hc.PwnedPassAPIOpts.HashMode = 99
	l, _, err = hc.PwnedPassAPI.ListHashesPrefix("a94a8")
	if err != nil {
		t.Errorf("ListHashesPrefix was not supposed to fail, but did: %s", err)
	}
	if len(l) <= 0 {
		t.Errorf("ListHashesPrefix was supposed to return a list longer than 0")
	}
}

// TestPwnedPassAPI_ListHashesPrefix_Errors tests the ListHashesPrefix method's errors
func TestPwnedPassAPI_ListHashesPrefix_Errors(t *testing.T) {
	hc := New()

	// Empty prefix
	t.Run("empty prefix", func(t *testing.T) {
		_, _, err := hc.PwnedPassAPI.ListHashesPrefix("")
		if err == nil {
			t.Errorf("ListHashesPrefix with empty prefix should fail but didn't")
			return
		}
		if !errors.Is(err, ErrPrefixLengthMismatch) {
			t.Errorf("ListHashesPrefix with empty prefix should return ErrPrefixLengthMismatch error but didn't")
			return
		}
	})

	// Too long prefix
	t.Run("too long prefix", func(t *testing.T) {
		_, _, err := hc.PwnedPassAPI.ListHashesPrefix("abcdefg12345")
		if err == nil {
			t.Errorf("ListHashesPrefix with too long prefix should fail but didn't")
			return
		}
		if !errors.Is(err, ErrPrefixLengthMismatch) {
			t.Errorf("ListHashesPrefix with too long prefix should return ErrPrefixLengthMismatch error but didn't")
		}
	})
}

// TestPwnedPassAPI_ListHashesSHA1_Errors tests the ListHashesSHA1 method's errors
func TestPwnedPassAPI_ListHashesSHA1_Errors(t *testing.T) {
	hc := New()

	// Empty hash
	t.Run("empty hash", func(t *testing.T) {
		_, _, err := hc.PwnedPassAPI.ListHashesSHA1("")
		if err == nil {
			t.Errorf("ListHashesSHA1 with empty hash should fail but didn't")
		}
		if !errors.Is(err, ErrSHA1LengthMismatch) {
			t.Errorf("ListHashesSHA1 with empty hash should return ErrSHA1LengthMismatch error but didn't")
		}
	})

	// Too long hash
	t.Run("too long hash", func(t *testing.T) {
		_, _, err := hc.PwnedPassAPI.ListHashesSHA1("FF36DC7D3284A39991ADA90CAF20D1E3C0DADEFAB")
		if err == nil {
			t.Errorf("ListHashesSHA1 with too long hash should fail but didn't")
		}
		if !errors.Is(err, ErrSHA1LengthMismatch) {
			t.Errorf("ListHashesSHA1 with too long hash should return ErrSHA1LengthMismatch error but didn't")
		}
	})

	// Invalid hash
	t.Run("invalid hash", func(t *testing.T) {
		_, _, err := hc.PwnedPassAPI.ListHashesSHA1("FF36DC7D3284A39991ADA90CAF20D1E3C0DADEFZ")
		if err == nil {
			t.Errorf("ListHashesSHA1 with invalid hash should fail but didn't")
		}
		if !errors.Is(err, ErrSHA1Invalid) {
			t.Errorf("ListHashesSHA1 with invalid hash should return ErrSHA1Invalid error but didn't")
		}
	})
}

// TestPwnedPassAPI_ListHashesNTLM_Errors tests the ListHashesNTLM method's errors
func TestPwnedPassAPI_ListHashesNTLM_Errors(t *testing.T) {
	hc := New()

	// Empty hash
	t.Run("empty hash", func(t *testing.T) {
		_, _, err := hc.PwnedPassAPI.ListHashesNTLM("")
		if err == nil {
			t.Errorf("ListHashesNTLM with empty hash should fail but didn't")
		}
		if !errors.Is(err, ErrNTLMLengthMismatch) {
			t.Errorf("ListHashesNTLM with empty hash should return ErrNTLMLengthMismatch error but didn't")
		}
	})

	// Too long hash
	t.Run("too long hash", func(t *testing.T) {
		_, _, err := hc.PwnedPassAPI.ListHashesNTLM("FF36DC7D3284A39991ADA90CAF20D1E3C0DADEFAB")
		if err == nil {
			t.Errorf("ListHashesNTLM with too long hash should fail but didn't")
		}
		if !errors.Is(err, ErrNTLMLengthMismatch) {
			t.Errorf("ListHashesNTLM with too long hash should return ErrNTLMLengthMismatch error but didn't")
		}
	})

	// Invalid hash
	t.Run("invalid hash", func(t *testing.T) {
		_, _, err := hc.PwnedPassAPI.ListHashesNTLM("3284A39991ADA90CAF20D1E3C0DADEFZ")
		if err == nil {
			t.Errorf("ListHashesNTLM with invalid hash should fail but didn't")
		}
		if !errors.Is(err, ErrNTLMInvalid) {
			t.Errorf("ListHashesNTLM with invalid hash should return ErrSHA1Invalid error but didn't")
		}
	})
}

// TestPwnedPassApi_ListHashesSHA1 tests the PwnedPassAPI.ListHashesSHA1 metethod
func TestPwnedPassAPI_ListHashesSHA1(t *testing.T) {
	hc := New()

	// List length should be >0
	l, _, err := hc.PwnedPassAPI.ListHashesSHA1(PwHashInsecure)
	if err != nil {
		t.Errorf("ListHashesSHA1 was not supposed to fail, but did: %s", err)
	}
	if len(l) <= 0 {
		t.Errorf("ListHashesSHA1 was supposed to return a list longer than 0")
	}

	// Hash has wrong size
	_, _, err = hc.PwnedPassAPI.ListHashesSHA1(PwStringInsecure)
	if err == nil {
		t.Errorf("ListHashesSHA1 was supposed to fail, but didn't")
	}
}

// TestPwnedPassApi_ListHashesNTLM tests the PwnedPassAPI.ListHashesNTLM metethod
func TestPwnedPassAPI_ListHashesNTLM(t *testing.T) {
	hc := New(WithPwnedNTLMHash())

	// List length should be >0
	l, _, err := hc.PwnedPassAPI.ListHashesNTLM(PwHashInsecureNTLM)
	if err != nil {
		t.Errorf("ListHashesNTLM was not supposed to fail, but did: %s", err)
	}
	if len(l) <= 0 {
		t.Errorf("ListHashesNTLM was supposed to return a list longer than 0")
	}

	// Hash has wrong size
	_, _, err = hc.PwnedPassAPI.ListHashesNTLM(PwStringInsecure)
	if err == nil {
		t.Errorf("ListHashesNTLM was supposed to fail, but didn't")
	}
}

// TestPwnedPassAPI_ListHashesPassword tests the PwnedPassAPI.ListHashesPassword metethod
func TestPwnedPassAPI_ListHashesPassword(t *testing.T) {
	hc := New()

	// List length should be >0
	l, _, err := hc.PwnedPassAPI.ListHashesPassword(PwStringInsecure)
	if err != nil {
		t.Errorf("ListHashesPassword was not supposed to fail, but did: %s", err)
	}
	if len(l) <= 0 {
		t.Errorf("ListHashesPassword was supposed to return a list longer than 0")
	}
}

// TestPwnedPassAPI_ListHashesPassword_failed tests the PwnedPassAPI.ListHashesPassword metethod
// with a unsupported HashMode
func TestPwnedPassAPI_ListHashesPassword_failed(t *testing.T) {
	hc := New()
	hc.PwnedPassAPIOpts.HashMode = 99

	_, _, err := hc.PwnedPassAPI.ListHashesPassword(PwStringInsecure)
	if err == nil {
		t.Error("ListHashesPassword with unspported HashMode was supposed to fail, but didn't")
	}
	if !errors.Is(err, ErrUnsupportedHashMode) {
		t.Errorf("ListHashesPassword error does not match, expected: %s, got: %s", ErrUnsupportedHashMode, err)
	}
}

// TestPwnedPassAPI_ListHashesPasswordNTLM tests the PwnedPassAPI.ListHashesPassword metethod
// with NTLM HashMode
func TestPwnedPassAPI_ListHashesPasswordNTLM(t *testing.T) {
	hc := New(WithPwnedNTLMHash())

	// List length should be >0
	l, _, err := hc.PwnedPassAPI.ListHashesPassword(PwStringInsecure)
	if err != nil {
		t.Errorf("ListHashesPassword was not supposed to fail, but did: %s", err)
	}
	if len(l) <= 0 {
		t.Errorf("ListHashesPassword was supposed to return a list longer than 0")
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
		fmt.Printf("Your password with the hash %q was found %d times in the pwned passwords DB\n",
			m.Hash, m.Count)
		// Output: Your password with the hash "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" was found 222947 times in the pwned passwords DB
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
		fmt.Printf("Your password with the hash %q was found %d times in the pwned passwords DB\n",
			m.Hash, m.Count)
		// Output: Your password with the hash "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" was found 222947 times in the pwned passwords DB
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
		fmt.Printf("Your password with the hash %q was found %d times in the pwned passwords DB\n",
			m.Hash, m.Count)
		// Output: Your password with the hash "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" was found 222947 times in the pwned passwords DB
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
		fmt.Printf("Your password with the hash %q was found %d times in the pwned passwords DB\n",
			m.Hash, m.Count)
		// Output: Your password with the hash "0cb6948805f797bf2a82807973b89537" was found 222947 times in the pwned passwords DB
	}
}


*/
