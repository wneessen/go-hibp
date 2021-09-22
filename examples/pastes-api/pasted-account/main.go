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
	pd, _, err := hc.PasteApi.PastedAccount("account-exists@hibp-integration-tests.com")
	if err != nil {
		panic(err)
	}
	for _, p := range pd {
		fmt.Printf("Your account was part of the %q paste\n", p.Title)
	}
}
