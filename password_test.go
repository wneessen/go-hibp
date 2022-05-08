package hibp

import (
	"fmt"
	"testing"
)

// TestPwnedPasswordString verifies the Pwned Passwords API with the CheckPassword method
func TestPwnedPasswordString(t *testing.T) {
	testTable := []struct {
		testName string
		pwString string
		isLeaked bool
	}{
		{"weak password 'test123' is expected to be leaked", "test123", true},
		{"strong, unknown password is expected to be not leaked",
			"F/0Ws#.%{Z/NVax=OU8Ajf1qTRLNS12p/?s/adX", false},
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

// TestPwnedPasswordHash verifies the Pwned Passwords API with the CheckSHA1 method
func TestPwnedPasswordHash(t *testing.T) {
	testTable := []struct {
		testName string
		pwHash   string
		isLeaked bool
	}{
		{"weak password 'test123' is expected to be leaked",
			"7288edd0fc3ffcbe93a0cf06e3568e28521687bc", true},
		{"strong, unknown password is expected to be not leaked",
			"90efc095c82eab44e882fda507cfab1a2cd31fc0", false},
	}
	hc := New()
	for _, tc := range testTable {
		t.Run(tc.testName, func(t *testing.T) {
			m, _, err := hc.PwnedPassApi.CheckSHA1(tc.pwHash)
			if err != nil {
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
		// Output: Your password with the hash "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" was found 86453 times in the pwned passwords DB
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
		// Output: Your password with the hash "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" was found 86453 times in the pwned passwords DB
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
		// Output: Your password with the hash "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" was found 86453 times in the pwned passwords DB
	}
}
