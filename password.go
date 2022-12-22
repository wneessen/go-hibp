package hibp

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// PwnedPassAPI is a HIBP Pwned Passwords API client
type PwnedPassAPI struct {
	hibp *Client // References back to the parent HIBP client
}

// Match represents a match in the Pwned Passwords API
type Match struct {
	Hash  string // SHA1 hash of the matching password
	Count int64  // Represents the number of leaked accounts that hold/held this password
}

// PwnedPasswordOptions is a struct of additional options for the PP API
type PwnedPasswordOptions struct {
	// WithPadding controls if the PwnedPassword API returns with padding or not
	// See: https://haveibeenpwned.com/API/v3#PwnedPasswordsPadding
	WithPadding bool
}

// CheckPassword checks the Pwned Passwords database against a given password string
func (p *PwnedPassAPI) CheckPassword(pw string) (*Match, *http.Response, error) {
	shaSum := fmt.Sprintf("%x", sha1.Sum([]byte(pw)))
	return p.CheckSHA1(shaSum)
}

// CheckSHA1 checks the Pwned Passwords database against a given SHA1 checksum of a password string
func (p *PwnedPassAPI) CheckSHA1(h string) (*Match, *http.Response, error) {
	if len(h) != 40 {
		return nil, nil, ErrSHA1LengthMismatch
	}

	pwMatches, hr, err := p.ListHashesPrefix(h[:5])
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

// ListHashesPassword checks the Pwned Password API endpoint for all hashes based on a given
// password string and returns the a slice of Match as well as the http.Response
//
// NOTE: If the `WithPwnedPadding` option is set to true, the returned list will be padded and might
// contain junk data
func (p *PwnedPassAPI) ListHashesPassword(pw string) ([]Match, *http.Response, error) {
	shaSum := fmt.Sprintf("%x", sha1.Sum([]byte(pw)))
	return p.ListHashesSHA1(shaSum)
}

// ListHashesSHA1 checks the Pwned Password API endpoint for all hashes based on a given
// SHA1 checksum and returns the a slice of Match as well as the http.Response
//
// NOTE: If the `WithPwnedPadding` option is set to true, the returned list will be padded and might
// contain junk data
func (p *PwnedPassAPI) ListHashesSHA1(h string) ([]Match, *http.Response, error) {
	if len(h) != 40 {
		return nil, nil, ErrSHA1LengthMismatch
	}
	dst := make([]byte, hex.DecodedLen(len(h)))
	if _, err := hex.Decode(dst, []byte(h)); err != nil {
		return nil, nil, ErrSHA1Invalid
	}
	return p.ListHashesPrefix(h[:5])
}

// ListHashesPrefix checks the Pwned Password API endpoint for all hashes based on a given
// SHA1 checksum prefix and returns the a slice of Match as well as the http.Response
//
// NOTE: If the `WithPwnedPadding` option is set to true, the returned list will be padded and might
// contain junk data
func (p *PwnedPassAPI) ListHashesPrefix(pf string) ([]Match, *http.Response, error) {
	if len(pf) != 5 {
		return nil, nil, ErrPrefixLengthMismatch
	}

	au := fmt.Sprintf("%s/range/%s", PasswdBaseURL, pf)
	hreq, err := p.hibp.HTTPReq(http.MethodGet, au, nil)
	if err != nil {
		return nil, nil, err
	}
	hr, err := p.hibp.hc.Do(hreq)
	if err != nil {
		return nil, hr, err
	}
	defer func() {
		_ = hr.Body.Close()
	}()
	if hr.StatusCode != 200 {
		return nil, hr, fmt.Errorf("HTTP %s: %w", hr.Status, ErrNonPositiveResponse)
	}

	var pm []Match
	so := bufio.NewScanner(hr.Body)
	for so.Scan() {
		hp := strings.SplitN(so.Text(), ":", 2)
		fh := fmt.Sprintf("%s%s", strings.ToLower(pf), strings.ToLower(hp[0]))
		hc, err := strconv.ParseInt(hp[1], 10, 64)
		if err != nil {
			continue
		}
		if hc == 0 {
			continue
		}
		pm = append(pm, Match{
			Hash:  fh,
			Count: hc,
		})
	}

	if err := so.Err(); err != nil {
		return nil, hr, err
	}

	return pm, hr, nil
}
