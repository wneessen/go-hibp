package hibp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// BreachApi is a HIBP breaches API client
type BreachApi struct {
	hibp *Client

	// Options
	domain string // Filter for a specific breach domain
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
	BreachDate *ApiDate `json:"BreachDate,omitempty"`

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
}

// BreachOption is an additional option the can be set for the BreachApiClient
type BreachOption func(*BreachApi)

// ApiDate is a date string without time returned by the API represented as time.Time type
type ApiDate time.Time

// Breaches returns a list of all breaches in the HIBP system
func (b *BreachApi) Breaches(options ...BreachOption) ([]*Breach, *http.Response, error) {
	for _, opt := range options {
		opt(b)
	}

	apiUrl := fmt.Sprintf("%s/breaches", BaseUrl)
	if b.domain != "" {
		apiUrl = fmt.Sprintf("%s?domain=%s", apiUrl, b.domain)
	}

	hreq, err := b.hibp.HttpReq(http.MethodGet, apiUrl)
	if err != nil {
		return nil, nil, err
	}
	hr, err := b.hibp.hc.Do(hreq)
	if err != nil {
		return nil, hr, err
	}
	if hr.StatusCode != 200 {
		return nil, hr, fmt.Errorf("API responded with non HTTP-200: %s", hr.Status)
	}
	defer func() {
		_ = hr.Body.Close()
	}()

	hb, err := io.ReadAll(hr.Body)
	if err != nil {
		return nil, hr, err
	}

	var breachList []*Breach
	if err := json.Unmarshal(hb, &breachList); err != nil {
		return nil, hr, err
	}

	return breachList, hr, nil
}

// WithDomain sets the domain filter for the breaches API
func WithDomain(d string) BreachOption {
	return func(b *BreachApi) {
		b.domain = d
	}
}

// UnmarshalJSON for the ApiDate type converts a give date string into a time.Time type
func (d *ApiDate) UnmarshalJSON(s []byte) error {
	ds := string(s)
	ds = strings.ReplaceAll(ds, `"`, ``)
	if ds == "null" {
		return nil
	}

	pd, err := time.Parse("2006-01-02", ds)
	if err != nil {
		return fmt.Errorf("failed to convert API date string to time.Time type: %s", err)
	}

	*(*time.Time)(d) = pd
	return nil
}

// Time adds a Time() method to the ApiDate converted time.Time type
func (d ApiDate) Time() time.Time {
	return time.Time(d)
}
