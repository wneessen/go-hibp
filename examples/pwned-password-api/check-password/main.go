package main

import (
	"fmt"
	"github.com/wneessen/go-hibp"
)

func main() {
	hc := hibp.New()
	m, _, err := hc.PwnedPassApi.CheckPassword("test")
	if err != nil {
		panic(err)
	}
	if m != nil && m.Count != 0 {
		fmt.Printf("Your password with the hash %q was found %d times in the pwned passwords DB\n",
			m.Hash, m.Count)
	}
}
