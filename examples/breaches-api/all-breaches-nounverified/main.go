package main

import (
	"fmt"
	"github.com/wneessen/go-hibp"
)

func main() {
	hc := hibp.New()
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
