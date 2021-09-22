package main

import (
	"fmt"
	"github.com/wneessen/go-hibp"
	"os"
)

func main() {
	apiKey := os.Getenv("HIBP_API_KEY")
	if apiKey == "" {
		panic("A API key is required for this API")
	}
	hc := hibp.New(hibp.WithApiKey(apiKey))
	bd, _, err := hc.BreachApi.BreachedAccount("multiple-breaches@hibp-integration-tests.com")
	if err != nil {
		panic(err)
	}
	for _, b := range bd {
		fmt.Printf("Your account was part of the %q breach\n", b.Name)
	}
}
