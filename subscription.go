// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev> et al
//
// SPDX-License-Identifier: MIT

package hibp

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type SubscriptionAPI struct {
	hibp *Client // References back to the parent HIBP client
}

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
	DomainSearchMaxBreachedAccounts *int `json:"DomainSearchMaxBreachedAccounts"`
}

// Status returns details of the current subscription.
func (s *SubscriptionAPI) Status() (*SubscriptionStatus, *http.Response, error) {
	au := fmt.Sprintf("%s/subscription/status", BaseURL)
	hb, hr, err := s.hibp.HTTPResBody(http.MethodGet, au, nil)
	if err != nil {
		return nil, hr, err
	}

	var subscriptionStatus *SubscriptionStatus
	if err := json.Unmarshal(hb, &subscriptionStatus); err != nil {
		return nil, hr, err
	}

	return subscriptionStatus, hr, nil
}
