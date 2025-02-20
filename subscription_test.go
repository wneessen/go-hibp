package hibp

import (
	"net/http"
	"os"
	"testing"
)

// TestSubscriptionAPI_Status tests the Status() method of the subscription API
func TestSubscriptionAPI_Status(t *testing.T) {
	t.Run("Unauthenticated", func(t *testing.T) {
		hc := New(WithRateLimitSleep())
		subscriptionStatus, httpResponse, err := hc.SubscriptionAPI.Status()
		if err == nil {
			t.Errorf("err is nil but expected a failure")
		}
		if httpResponse == nil {
			t.Errorf("httpResponse is nil")
		} else {
			if httpResponse.StatusCode != http.StatusUnauthorized {
				t.Errorf("unexpected status code: %d", httpResponse.StatusCode)
			}
		}
		if subscriptionStatus != nil {
			t.Errorf("subscriptionStatus is not nil")
		}
	})
	t.Run("Authenticated", func(t *testing.T) {
		apiKey := os.Getenv("HIBP_API_KEY")
		if apiKey == "" {
			t.SkipNow()
		}
		hc := New(WithAPIKey(apiKey), WithRateLimitSleep())

		subscriptionStatus, httpResponse, err := hc.SubscriptionAPI.Status()
		if err != nil {
			t.Error(err)
		}
		if httpResponse == nil {
			t.Errorf("httpResponse is nil")
		} else {
			if httpResponse.StatusCode != http.StatusOK {
				t.Errorf("unexpected status code: %d", httpResponse.StatusCode)
			}
		}
		if subscriptionStatus == nil {
			t.Errorf("subscriptionStatus is nil")
		} else {
			if subscriptionStatus.Description == "" {
				t.Errorf("Description is empty")
			}
			if subscriptionStatus.SubscriptionName == "" {
				t.Errorf("SubscriptionName is empty")
			}
			if subscriptionStatus.Rpm <= 0 {
				t.Errorf("Rpm is impossible")
			}
		}
	})
}
