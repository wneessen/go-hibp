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

	bl, _, err := hc.BreachApi.Breaches()
	if err != nil {
		panic(err)
	}
	if bl != nil && len(bl) != 0 {
		fmt.Printf("Found %d breaches total.\n", len(bl))
	}

	bl, _, err = hc.BreachApi.Breaches(hibp.WithoutUnverified())
	if err != nil {
		panic(err)
	}
	if bl != nil && len(bl) != 0 {
		fmt.Printf("Found %d verified breaches total.\n", len(bl))
	}
}
