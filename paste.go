package hibp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// PasteApi is a HIBP pastes API client
type PasteApi struct {
	hibp *Client // References back to the parent HIBP client
}

// Paste represents a JSON response structure of the pastes API
type Paste struct {
	// Source is the paste service the record was retrieved from. Current values are: Pastebin,
	// Pastie, Slexy, Ghostbin, QuickLeak, JustPaste, AdHocUrl, PermanentOptOut, OptOut
	Source string `json:"Source"`

	// Id of the paste as it was given at the source service. Combined with the "Source" attribute, this
	// can be used to resolve the URL of the paste
	Id string `json:"Id"`

	// Title of the paste as observed on the source site. This may be null and if so will be omitted from
	// the response
	Title string `json:"Title"`

	// Date is the date and time (precision to the second) that the paste was posted. This is taken directly
	// from the paste site when this information is available but may be null if no date is published
	Date time.Time `json:"Date"`

	// EmailCount is number of emails that were found when processing the paste. Emails are extracted by
	// using the regular expression \b[a-zA-Z0-9\.\-_\+]+@[a-zA-Z0-9\.\-_]+\.[a-zA-Z]+\b
	EmailCount int `json:"EmailCount"`
}

// PastedAccount returns a single breached site based on its name
func (p *PasteApi) PastedAccount(a string) ([]*Paste, *http.Response, error) {
	if a == "" {
		return nil, nil, fmt.Errorf("no account id given")
	}

	apiUrl := fmt.Sprintf("%s/pasteaccount/%s", BaseUrl, a)
	hb, hr, err := p.hibp.HttpResBody(http.MethodGet, apiUrl, nil)
	if err != nil {
		return nil, nil, err
	}

	var pasteDetails []*Paste
	if err := json.Unmarshal(hb, &pasteDetails); err != nil {
		return nil, hr, err
	}

	return pasteDetails, hr, nil
}
