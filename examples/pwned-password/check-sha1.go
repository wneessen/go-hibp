package main

import (
	"fmt"
	hibp "github.com/wneessen/go-hibp"
)

func main() {
	hc := hibp.New()
	if hc == nil {
		panic("failed to create HIBP client")
	}

	pwHash := "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" // represents the PW: "test"
	m, _, err := hc.PwnedPassApi.CheckSHA1(pwHash)
	if err != nil {
		panic(err)
	}
	if m != nil && m.Count != 0 {
		fmt.Printf("Your password with the hash %q was found %d times in the pwned passwords DB\n",
			m.Hash, m.Count)
	}
}
