// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev> et al
//
// SPDX-License-Identifier: MIT

package hibp

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/wneessen/niljson"
)

// SubscriptionAPI provides methods to interact with the subscription endpoint of the HIBP API.
type SubscriptionAPI struct {
	hibp *Client // References back to the parent HIBP client
}

// SubscriptionStatus represents the details of a subscription including its name, description, expiration,
// and limitations.
type SubscriptionStatus struct {
	// SubscriptionName is the name representing the subscription being either "Pwned 1", "Pwned 2", "Pwned 3" or "Pwned 4".
	SubscriptionName string `json:"SubscriptionName"`

	// Description is a human readable sentence explaining the scope of the subscription.
	Description string `json:"Description"`

	// SubscribedUntil is the date and time the current subscription ends in ISO 8601 format.
	SubscribedUntil APIDate `json:"SubscribedUntil"`

	// Rpm is the rate limit in requests per minute. This applies to the rate the breach search by email address API can be requested.
	Rpm int `json:"Rpm"`

	// DomainSearchMaxBreachedAccounts is the size of the largest domain the subscription can search.
	// This is expressed in the total number of breached accounts on the domain, excluding those that appear solely in spam list.
	// This will be nil if there is no limit.
	DomainSearchMaxBreachedAccounts niljson.NilInt `json:"DomainSearchMaxBreachedAccounts"`

	// present is an internal indicator. It is set to true if the Paste was returned by the HIBP API.
	// It can be used to make sure if a returned Paste was empty or not.
	present bool
}

// Status returns details of the current subscription.
// This API is authenticated and requires a valid API key.
//
// Reference: https://haveibeenpwned.com/API/v3#SubscriptionStatus
func (s *SubscriptionAPI) Status() (SubscriptionStatus, *http.Response, error) {
	var status SubscriptionStatus
	au := fmt.Sprintf("%s/subscription/status", BaseURL)
	hb, hr, err := s.hibp.HTTPResBody(http.MethodGet, au, nil)
	if err != nil {
		return status, hr, err
	}

	if err = json.Unmarshal(hb, &status); err != nil {
		return status, hr, err
	}
	status.present = true

	return status, hr, nil
}

// Present indicates whether the SubscriptionStatus object has been returned by the HIBP API.
func (s SubscriptionStatus) Present() bool {
	return s.present
}
