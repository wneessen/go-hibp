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

// PasteAPI is a HIBP pastes API client
type PasteAPI struct {
	hibp *Client // References back to the parent HIBP client
}

// Paste represents a JSON response structure of the pastes API
type Paste struct {
	// Source is the paste service the record was retrieved from. Current values are: Pastebin,
	// Pastie, Slexy, Ghostbin, QuickLeak, JustPaste, AdHocUrl, PermanentOptOut, OptOut
	Source string `json:"Source"`

	// ID of the paste as it was given at the source service. Combined with the "Source" attribute, this
	// can be used to resolve the URL of the paste
	ID string `json:"ID"`

	// Title of the paste as observed on the source site. This may be null and if so will be omitted from
	// the response
	Title string `json:"Title"`

	// Date is the date and time (precision to the second) that the paste was posted. This is taken directly
	// from the paste site when this information is available but may be null if no date is published
	Date time.Time `json:"Date"`

	// EmailCount is number of emails that were found when processing the paste. Emails are extracted by
	// using the regular expression \b[a-zA-Z0-9\.\-_\+]+@[a-zA-Z0-9\.\-_]+\.[a-zA-Z]+\b
	EmailCount int `json:"EmailCount"`

	// present is an internal indicator. It is set to true if the Paste was returned by the HIBP API.
	// It can be used to make sure if a returned Paste was empty or not.
	present bool
}

// PastedAccount returns a single breached site based on its name
func (p *PasteAPI) PastedAccount(a string) ([]Paste, *http.Response, error) {
	if a == "" {
		return nil, nil, ErrNoAccountID
	}

	au := fmt.Sprintf("%s/pasteaccount/%s", BaseURL, a)
	hb, hr, err := p.hibp.HTTPResBody(http.MethodGet, au, nil)
	if err != nil {
		if hr != nil && hr.StatusCode == http.StatusNotFound {
			return nil, hr, nil
		}
		return nil, hr, err
	}

	var pd []Paste
	if err = json.Unmarshal(hb, &pd); err != nil {
		return nil, hr, err
	}
	for i := range pd {
		pd[i].present = true
	}

	return pd, hr, nil
}

// Present indicates whether the Paste object has been returned by the HIBP API.
func (p Paste) Present() bool {
	return p.present
}
