package main

import (
	"fmt"
	"github.com/wneessen/go-hibp"
)

func main() {
	hc := hibp.New()
	bd, _, err := hc.BreachApi.BreachByName("Adobe")
	if err != nil {
		panic(err)
	}
	if bd != nil {
		fmt.Println("Details of the 'Adobe' breach:")
		fmt.Printf("\tDomain: %s\n", bd.Domain)
		fmt.Printf("\tBreach date: %s\n", bd.BreachDate.Time().Format("2006-01-02"))
		fmt.Printf("\tAdded to HIBP: %s\n", bd.AddedDate.String())

	}
}
