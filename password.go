package hibp

import (
	"bufio"
	"crypto/sha1"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// PwnedPassword is a HIBP Pwned Passwords API client
type PwnedPassword struct {
	hc *Client
}

// Match represents a match in the Pwned Passwords API
type Match struct {
	Hash  string
	Count int64
}

// CheckPassword checks the Pwned Passwords database against a given password string
func (p *PwnedPassword) CheckPassword(pw string) (*Match, *http.Response, error) {
	shaSum := fmt.Sprintf("%x", sha1.Sum([]byte(pw)))
	return p.CheckSHA1(shaSum)
}

// CheckSHA1 checks the Pwned Passwords database against a given SHA1 checksum of a password
func (p *PwnedPassword) CheckSHA1(h string) (*Match, *http.Response, error) {
	pwMatches, hr, err := p.apiCall(h)
	if err != nil {
		return &Match{}, hr, err
	}

	for _, m := range pwMatches {
		if m.Hash == h {
			return &m, hr, nil
		}
	}

	return nil, hr, nil
}

// apiCall performs the API call to the Pwned Password API endpoint and returns
// the http.Response
func (p *PwnedPassword) apiCall(h string) ([]Match, *http.Response, error) {
	sh := h[:5]
	hreq, err := p.hc.HttpReq(http.MethodGet, fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", sh))
	if err != nil {
		return nil, nil, err
	}
	hr, err := p.hc.hc.Do(hreq)
	if err != nil {
		return nil, nil, err
	}
	if hr.StatusCode != 200 {
		return nil, hr, fmt.Errorf("API responded with non HTTP-200: %s", hr.Status)
	}
	defer func() {
		_ = hr.Body.Close()
	}()

	var pwMatches []Match
	scanObj := bufio.NewScanner(hr.Body)
	for scanObj.Scan() {
		hp := strings.SplitN(scanObj.Text(), ":", 2)
		fh := fmt.Sprintf("%s%s", sh, strings.ToLower(hp[0]))
		hc, err := strconv.ParseInt(hp[1], 10, 64)
		if err != nil {
			continue
		}
		pwMatches = append(pwMatches, Match{
			Hash:  fh,
			Count: hc,
		})
	}

	if err := scanObj.Err(); err != nil {
		return nil, nil, err
	}

	return pwMatches, hr, nil
}
