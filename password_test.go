package hibp

import (
	"fmt"
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

	// PwHashSecure is the SHA1 checksum of a secure password
	// Represents the string: F/0Ws#.%{Z/NVax=OU8Ajf1qTRLNS12p/?s/adX
	PwHashSecure = "90efc095c82eab44e882fda507cfab1a2cd31fc0"
)

// TestPwnedPassApi_CheckPassword verifies the Pwned Passwords API with the CheckPassword method
func TestPwnedPassApi_CheckPassword(t *testing.T) {
	testTable := []struct {
		testName string
		pwString string
		isLeaked bool
	}{
		{"weak password 'test123' is expected to be leaked", PwStringInsecure, true},
		{"strong, unknown password is expected to be not leaked",
			PwStringSecure, false},
	}
	hc := New()
	for _, tc := range testTable {
		t.Run(tc.testName, func(t *testing.T) {
			m, _, err := hc.PwnedPassApi.CheckPassword(tc.pwString)
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
	}
}

// TestPwnedPassApi_CheckSHA1 verifies the Pwned Passwords API with the CheckSHA1 method
func TestPwnedPassApi_CheckSHA1(t *testing.T) {
	testTable := []struct {
		testName   string
		pwHash     string
		isLeaked   bool
		shouldFail bool
	}{
		{"weak password 'test' is expected to be leaked",
			PwHashInsecure, true, false},
		{"strong, unknown password is expected to be not leaked",
			PwHashSecure, false, false},
		{"empty string should fail",
			"", false, true},
	}
	hc := New()
	for _, tc := range testTable {
		t.Run(tc.testName, func(t *testing.T) {
			m, _, err := hc.PwnedPassApi.CheckSHA1(tc.pwHash)
			if err != nil && !tc.shouldFail {
				t.Error(err)
				return
			}
			if m == nil && tc.isLeaked {
				t.Errorf("password is expected to be leaked but 0 leaks were returned in Pwned Passwords DB")
			}
			if m != nil && m.Count > 0 && !tc.isLeaked {
				t.Errorf("password is not expected to be leaked but %d leaks were found in Pwned Passwords DB",
					m.Count)
			}
		})
	}
}

// TestPwnedPassApi_ListHashesPrefix tests the ListHashesPrefix method (especially for failures that are not
// tested by the other tests already)
func TestPwnedPassApi_ListHashesPrefix(t *testing.T) {
	hc := New()

	// Should return at least 1 restults
	l, _, err := hc.PwnedPassApi.ListHashesPrefix("a94a8")
	if err != nil {
		t.Errorf("ListHashesPrefix was not supposed to fail, but did: %s", err)
	}
	if len(l) <= 0 {
		t.Errorf("ListHashesPrefix was supposed to return a list longer than 0")
	}

	// Prefix has wrong size
	_, _, err = hc.PwnedPassApi.ListHashesPrefix("ZZZZZZZZZZZZZZ")
	if err == nil {
		t.Errorf("ListHashesPrefix was supposed to fail, but didn't")
	}

	// Non allowed characters
	_, _, err = hc.PwnedPassApi.ListHashesPrefix(string([]byte{0, 0, 0, 0, 0}))
	if err == nil {
		t.Errorf("ListHashesPrefix was supposed to fail, but didn't")
	}
}

// TestPwnedPassApi_ListHashesSHA1 tests the PwnedPassApi.ListHashesSHA1 metethod
func TestPwnedPassApi_ListHashesSHA1(t *testing.T) {
	hc := New()

	// List length should be >0
	l, _, err := hc.PwnedPassApi.ListHashesSHA1(PwHashInsecure)
	if err != nil {
		t.Errorf("ListHashesSHA1 was not supposed to fail, but did: %s", err)
	}
	if len(l) <= 0 {
		t.Errorf("ListHashesSHA1 was supposed to return a list longer than 0")
	}

	// Hash has wrong size
	_, _, err = hc.PwnedPassApi.ListHashesSHA1(PwStringInsecure)
	if err == nil {
		t.Errorf("ListHashesSHA1 was supposed to fail, but didn't")
	}
}

// TestPwnedPassApi_ListHashesPassword tests the PwnedPassApi.ListHashesPassword metethod
func TestPwnedPassApi_ListHashesPassword(t *testing.T) {
	hc := New()

	// List length should be >0
	l, _, err := hc.PwnedPassApi.ListHashesPassword(PwStringInsecure)
	if err != nil {
		t.Errorf("ListHashesPassword was not supposed to fail, but did: %s", err)
	}
	if len(l) <= 0 {
		t.Errorf("ListHashesPassword was supposed to return a list longer than 0")
	}

	// Empty string has no checksum
	_, _, err = hc.PwnedPassApi.ListHashesSHA1("")
	if err == nil {
		t.Errorf("ListHashesPassword was supposed to fail, but didn't")
	}
}

// ExamplePwnedPassApi_CheckPassword is a code example to show how to check a given password
// against the HIBP passwords API
func ExamplePwnedPassApi_CheckPassword() {
	hc := New()
	m, _, err := hc.PwnedPassApi.CheckPassword("test")
	if err != nil {
		panic(err)
	}
	if m != nil && m.Count != 0 {
		fmt.Printf("Your password with the hash %q was found %d times in the pwned passwords DB\n",
			m.Hash, m.Count)
		// Output: Your password with the hash "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" was found 86495 times in the pwned passwords DB
	}
}

// ExamplePwnedPassApi_CheckPassword_withPadding is a code example to show how to check a given password
// against the HIBP passwords API with the WithPadding() option set
func ExamplePwnedPassApi_CheckPassword_withPadding() {
	hc := New(WithPwnedPadding())
	m, _, err := hc.PwnedPassApi.CheckPassword("test")
	if err != nil {
		panic(err)
	}
	if m != nil && m.Count != 0 {
		fmt.Printf("Your password with the hash %q was found %d times in the pwned passwords DB\n",
			m.Hash, m.Count)
		// Output: Your password with the hash "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" was found 86495 times in the pwned passwords DB
	}
}

// ExamplePwnedPassApi_CheckSHA1 is a code example to show how to check a given password SHA1 hash
// against the HIBP passwords API using the CheckSHA1() method
func ExamplePwnedPassApi_CheckSHA1() {
	hc := New()
	pwHash := "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" // represents the PW: "test"
	m, _, err := hc.PwnedPassApi.CheckSHA1(pwHash)
	if err != nil {
		panic(err)
	}
	if m != nil && m.Count != 0 {
		fmt.Printf("Your password with the hash %q was found %d times in the pwned passwords DB\n",
			m.Hash, m.Count)
		// Output: Your password with the hash "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" was found 86495 times in the pwned passwords DB
	}
}
