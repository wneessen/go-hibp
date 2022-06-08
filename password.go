package hibp

import (
	"bufio"
	"crypto/sha1"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const (
	// ErrPrefixLengthMismatch should be used if a given prefix does not match the
	// expected length
	ErrPrefixLengthMismatch = "password hash prefix must be 5 characters long"

	// ErrSHA1LengthMismatch should be used if a given SHA1 checksum does not match the
	// expected length
	ErrSHA1LengthMismatch = "SHA1 hash size needs to be 160 bits"
)

// PwnedPassApi is a HIBP Pwned Passwords API client
type PwnedPassApi struct {
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
func (p *PwnedPassApi) CheckPassword(pw string) (*Match, *http.Response, error) {
	shaSum := fmt.Sprintf("%x", sha1.Sum([]byte(pw)))
	return p.CheckSHA1(shaSum)
}

// CheckSHA1 checks the Pwned Passwords database against a given SHA1 checksum of a password string
func (p *PwnedPassApi) CheckSHA1(h string) (*Match, *http.Response, error) {
	if len(h) != 40 {
		return nil, nil, fmt.Errorf(ErrSHA1LengthMismatch)
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
func (p *PwnedPassApi) ListHashesPassword(pw string) ([]Match, *http.Response, error) {
	shaSum := fmt.Sprintf("%x", sha1.Sum([]byte(pw)))
	return p.ListHashesSHA1(shaSum)
}

// ListHashesSHA1 checks the Pwned Password API endpoint for all hashes based on a given
// SHA1 checksum and returns the a slice of Match as well as the http.Response
//
// NOTE: If the `WithPwnedPadding` option is set to true, the returned list will be padded and might
// contain junk data
func (p *PwnedPassApi) ListHashesSHA1(h string) ([]Match, *http.Response, error) {
	if len(h) != 40 {
		return nil, nil, fmt.Errorf(ErrSHA1LengthMismatch)
	}
	return p.ListHashesPrefix(h[:5])
}

// ListHashesPrefix checks the Pwned Password API endpoint for all hashes based on a given
// SHA1 checksum prefix and returns the a slice of Match as well as the http.Response
//
// NOTE: If the `WithPwnedPadding` option is set to true, the returned list will be padded and might
// contain junk data
func (p *PwnedPassApi) ListHashesPrefix(pf string) ([]Match, *http.Response, error) {
	if len(pf) != 5 {
		return nil, nil, fmt.Errorf(ErrPrefixLengthMismatch)
	}
	hreq, err := p.hibp.HttpReq(http.MethodGet, fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", pf),
		nil)
	if err != nil {
		return nil, nil, err
	}
	hr, err := p.hibp.hc.Do(hreq)
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
		fh := fmt.Sprintf("%s%s", strings.ToLower(pf), strings.ToLower(hp[0]))
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
