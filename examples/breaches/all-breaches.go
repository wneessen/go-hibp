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
		for _, b := range bl {
			fmt.Printf("Found breach:\n\tName: %s\n\tDomain: %s\n\tBreach date: %s\n\n",
				b.Name, b.Domain, b.BreachDate.Time().Format("Mon, 2. January 2006"))
		}
	}
}
