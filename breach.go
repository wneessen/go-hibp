// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev> et al
//
// SPDX-License-Identifier: MIT

package hibp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// BreachAPI is a HIBP breaches API client
type BreachAPI struct {
	hibp *Client // References back to the parent HIBP client

	domain       string // Filter for a specific breach domain
	disableTrunc bool   // Controls the truncateResponse parameter for the breaches API (defaults to false)
	noUnverified bool   // Controls the includeUnverified parameter for the breaches API (defaults to false)
}

// Breach represents a JSON response structure of the breaches API
type Breach struct {
	// Name is a pascal-cased name representing the breach which is unique across all other breaches.
	// This value never changes and may be used to name dependent assets (such as images) but should not
	// be shown directly to end users (see the "Title" attribute instead)
	Name string `json:"Name"`

	// Title is a descriptive title for the breach suitable for displaying to end users. It's unique across
	// all breaches but individual values may change in the future (i.e. if another breach occurs against
	// an organisation already in the system). If a stable value is required to reference the breach,
	// refer to the "Name" attribute instead
	Title string `json:"Title"`

	// Domain of the primary website the breach occurred on. This may be used for identifying other
	// assets external systems may have for the site
	Domain string `json:"Domain"`

	// BreachDate is the date (with no time) the breach originally occurred on in ISO 8601 format. This is not
	// always accurate — frequently breaches are discovered and reported long after the original incident. Use
	// this attribute as a guide only
	BreachDate *APIDate `json:"BreachDate,omitempty"`

	// AddedDate represents the date and time (precision to the minute) the breach was added to the system
	// in ISO 8601 format
	AddedDate time.Time `json:"AddedDate"`

	// ModifiedDate is the date and time (precision to the minute) the breach was modified in ISO 8601 format.
	// This will only differ from the AddedDate attribute if other attributes represented here are changed or
	// data in the breach itself is changed (i.e. additional data is identified and loaded). It is always
	// either equal to or greater then the AddedDate attribute, never less than
	ModifiedDate time.Time `json:"ModifiedDate"`

	// PwnCount is the total number of accounts loaded into the system. This is usually less than the total
	// number reported by the media due to duplication or other data integrity issues in the source data
	PwnCount int `json:"PwnCount"`

	// Description contains an overview of the breach represented in HTML markup. The description may include
	// markup such as emphasis and strong tags as well as hyperlinks
	Description string `json:"Description"`

	// DataClasses describes the nature of the data compromised in the breach and contains an alphabetically ordered
	// string array of impacted data classes
	DataClasses []string `json:"DataClasses"`

	// IsVerified indicates that the breach is considered unverified. An unverified breach may not have
	// been hacked from the indicated website. An unverified breach is still loaded into HIBP when there's
	// sufficient confidence that a significant portion of the data is legitimate
	IsVerified bool `json:"IsVerified"`

	// IsFabricated indicates that the breach is considered fabricated. A fabricated breach is unlikely
	// to have been hacked from the indicated website and usually contains a large amount of manufactured
	// data. However, it still contains legitimate email addresses and asserts that the account owners
	// were compromised in the alleged breach
	IsFabricated bool `json:"IsFabricated"`

	// IsSensitive indicates if the breach is considered sensitive. The public API will not return any
	// accounts for a breach flagged as sensitive
	IsSensitive bool `json:"IsSensitive"`

	// IsRetired indicates if the breach has been retired. This data has been permanently removed and
	// will not be returned by the API
	IsRetired bool `json:"IsRetired"`

	// IsSpamList indicates
	IsSpamList bool `json:"IsSpamList"`

	// LogoPath represents a URI that specifies where a logo for the breached service can be found.
	// Logos are always in PNG format
	LogoPath string `json:"LogoPath"`
}

type SubscribedDomains struct {
	// DomainName is the full domain name that has been successfully verified.
	DomainName string `json:"DomainName"`

	// PwnCount is the total number of breached email addresses found on the domain at last search
	// (will be null if no searches yet performed).
	PwnCount *int `json:"PwnCount"`

	// PwnCountExcludingSpamLists is the number of breached email addresses found on the domain
	// at last search, excluding any breaches flagged as a spam list (will be null if no
	// searches yet performed).
	PwnCountExcludingSpamLists *int `json:"PwnCountExcludingSpamLists"`

	// The total number of breached email addresses found on the domain when the current
	// subscription was taken out (will be null if no searches yet performed). This number
	// ensures the domain remains searchable throughout the subscription period even if the
	// volume of breached accounts grows beyond the subscription's scope.
	PwnCountExcludingSpamListsAtLastSubscriptionRenewal *int `json:"PwnCountExcludingSpamListsAtLastSubscriptionRenewal"`

	// The date and time the current subscription ends in ISO 8601 format. The
	// PwnCountExcludingSpamListsAtLastSubscriptionRenewal value is locked in until this time (will
	// be null if there have been no subscriptions).
	NextSubscriptionRenewal RenewalTime `json:"NextSubscriptionRenewal"`
}

// BreachOption is an additional option the can be set for the BreachApiClient
type BreachOption func(*BreachAPI)

// APIDate is a date string without time returned by the API represented as time.Time type
type APIDate time.Time

// RenewalTime is a timestamp returned by the API that doesn't have timezone information
type RenewalTime time.Time

// Breaches returns a list of all breaches in the HIBP system
func (b *BreachAPI) Breaches(options ...BreachOption) ([]*Breach, *http.Response, error) {
	qp := b.setBreachOpts(options...)
	au := fmt.Sprintf("%s/breaches", BaseURL)

	hb, hr, err := b.hibp.HTTPResBody(http.MethodGet, au, qp)
	if err != nil {
		return nil, hr, err
	}

	var bl []*Breach
	if err := json.Unmarshal(hb, &bl); err != nil {
		return nil, hr, err
	}

	return bl, hr, nil
}

// BreachByName returns a single breached site based on its name
func (b *BreachAPI) BreachByName(n string, options ...BreachOption) (*Breach, *http.Response, error) {
	qp := b.setBreachOpts(options...)

	if n == "" {
		return nil, nil, ErrNoName
	}

	au := fmt.Sprintf("%s/breach/%s", BaseURL, n)
	hb, hr, err := b.hibp.HTTPResBody(http.MethodGet, au, qp)
	if err != nil {
		return nil, hr, err
	}

	var bd *Breach
	if err := json.Unmarshal(hb, &bd); err != nil {
		return nil, hr, err
	}

	return bd, hr, nil
}

// LatestBreach returns the single most recent breach
func (b *BreachAPI) LatestBreach() (*Breach, *http.Response, error) {
	au := fmt.Sprintf("%s/latestbreach", BaseURL)
	hb, hr, err := b.hibp.HTTPResBody(http.MethodGet, au, nil)
	if err != nil {
		return nil, hr, err
	}

	var bd *Breach
	if err := json.Unmarshal(hb, &bd); err != nil {
		return nil, hr, err
	}

	return bd, hr, nil
}

// DataClasses are attribute of a record compromised in a breach. This method returns a list of strings
// with all registered data classes known to HIBP
func (b *BreachAPI) DataClasses() ([]string, *http.Response, error) {
	au := fmt.Sprintf("%s/dataclasses", BaseURL)
	hb, hr, err := b.hibp.HTTPResBody(http.MethodGet, au, nil)
	if err != nil {
		return nil, hr, err
	}

	var dc []string
	if err := json.Unmarshal(hb, &dc); err != nil {
		return nil, hr, err
	}

	return dc, hr, nil
}

// BreachedAccount returns a single breached site based on its name
func (b *BreachAPI) BreachedAccount(a string, options ...BreachOption) ([]*Breach, *http.Response, error) {
	qp := b.setBreachOpts(options...)

	if a == "" {
		return nil, nil, ErrNoAccountID
	}

	au := fmt.Sprintf("%s/breachedaccount/%s", BaseURL, a)
	hb, hr, err := b.hibp.HTTPResBody(http.MethodGet, au, qp)
	if err != nil {
		return nil, hr, err
	}

	var bd []*Breach
	if err := json.Unmarshal(hb, &bd); err != nil {
		return nil, hr, err
	}

	return bd, hr, nil
}

// SubscribedDomains returns domains that have been successfully added to the domain
// search dashboard after verifying control are returned via this API. This is an
// authenticated API requiring an HIBP API key which will then return all domains associated with that key.
func (b *BreachAPI) SubscribedDomains() ([]SubscribedDomains, *http.Response, error) {
	au := fmt.Sprintf("%s/subscribeddomains", BaseURL)
	hb, hr, err := b.hibp.HTTPResBody(http.MethodGet, au, nil)
	if err != nil {
		return nil, hr, err
	}

	var bd []SubscribedDomains
	if err := json.Unmarshal(hb, &bd); err != nil {
		return nil, hr, err
	}

	return bd, hr, nil
}

// BreachedDomain returns all email addresses on a given domain and the breaches they've appeared
// in can be returned via the domain search API. Only domains that have been successfully added
// to the domain search dashboard after verifying control can be searched.
func (b *BreachAPI) BreachedDomain(domain string) (map[string][]string, *http.Response, error) {
	au := fmt.Sprintf("%s/breacheddomain/%s", BaseURL, domain)
	hb, hr, err := b.hibp.HTTPResBody(http.MethodGet, au, nil)
	if err != nil {
		return nil, hr, err
	}

	var bd map[string][]string
	if err := json.Unmarshal(hb, &bd); err != nil {
		return nil, hr, err
	}

	return bd, hr, nil
}

// WithDomain sets the domain filter for the breaches API
func WithDomain(d string) BreachOption {
	return func(b *BreachAPI) {
		b.domain = d
	}
}

// WithoutTruncate disables the truncateResponse parameter in the breaches API
// This option only influences the BreachedAccount method
func WithoutTruncate() BreachOption {
	return func(b *BreachAPI) {
		b.disableTrunc = true
	}
}

// WithoutUnverified suppress unverified breaches from the query
func WithoutUnverified() BreachOption {
	return func(b *BreachAPI) {
		b.noUnverified = true
	}
}

// UnmarshalJSON for the APIDate type converts a give date string into a time.Time type
func (d *APIDate) UnmarshalJSON(s []byte) error {
	ds := string(s[1 : len(s)-1])
	if ds == "null" || ds == "" {
		return nil
	}

	pd, err := time.Parse("2006-01-02", ds)
	if err != nil {
		return fmt.Errorf("convert API date string to time.Time type: %w", err)
	}

	*(*time.Time)(d) = pd
	return nil
}

// Time adds a Time() method to the APIDate converted time.Time type
func (d *APIDate) Time() time.Time {
	dp := *d
	return time.Time(dp)
}

// UnmarshalJSON for the RenewalTime type converts a give date string into a time.Time type
func (d *RenewalTime) UnmarshalJSON(s []byte) error {
	ds := string(s[1 : len(s)-1])
	if ds == "null" || ds == "" {
		return nil
	}

	pd, err := time.Parse("2006-01-02T15:04:05", ds)
	if err != nil {
		return fmt.Errorf("convert API date string to time.Time type: %w", err)
	}

	*(*time.Time)(d) = pd
	return nil
}

// Time adds a Time() method to the RenewalTime converted time.Time type
func (d *RenewalTime) Time() time.Time {
	dp := *d
	return time.Time(dp)
}

// setBreachOpts returns a map of default settings and overridden values from different BreachOption
func (b *BreachAPI) setBreachOpts(options ...BreachOption) map[string]string {
	qp := map[string]string{
		"truncateResponse":  "true",
		"includeUnverified": "true",
	}

	for _, opt := range options {
		if opt == nil {
			continue
		}
		opt(b)
	}

	if b.domain != "" {
		qp["domain"] = b.domain
	}

	if b.disableTrunc {
		qp["truncateResponse"] = "false"
	}

	if b.noUnverified {
		qp["includeUnverified"] = "false"
	}

	return qp
}
