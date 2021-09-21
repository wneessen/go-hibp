package hibp

import (
	"fmt"
	"os"
	"testing"
)

// TestNew tests the New() function
func TestBreach(t *testing.T) {
	hc := New(WithApiKey(os.Getenv("HIBP_API_KE")))
	if hc == nil {
		t.Errorf("hibp client creation failed")
	}
	foo, _, err := hc.BreachApi.Breaches(WithDomain("adobe.com"))
	if err != nil {
		t.Error(err)
	}
	for _, b := range foo {
		fmt.Printf("%+v", *b)
		if b.BreachDate != nil {
			fmt.Printf("%+v", b.BreachDate.Time().String())
		}
		break
	}
}
