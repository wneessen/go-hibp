// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev> et al
//
// SPDX-License-Identifier: MIT

package hibp

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/wneessen/go-hibp/md4"
)

// PwnedPassAPI is a HIBP Pwned Passwords API client
type PwnedPassAPI struct {
	// References back to the parent HIBP client
	hibp *Client
	// Query parameter map for additional query parameters passed to request
	ParamMap map[string]string
}

// Match represents a match in the Pwned Passwords API
type Match struct {
	Hash  string // SHA1 hash of the matching password
	Count int64  // Represents the number of leaked accounts that hold/held this password

	// present is an internal indicator. It is set to true if the Match was returned by the HIBP API.
	// It can be used to make sure if a returned Match was empty or not.
	present bool
}

type HashMode int

const (
	// HashModeSHA1 is the default hash mode expecting SHA-1 hashes
	HashModeSHA1 HashMode = iota
	// HashModeNTLM represents the mode that expects and returns NTLM hashes
	HashModeNTLM
)

// PwnedPasswordOptions is a struct of additional options for the PP API
type PwnedPasswordOptions struct {
	// HashMode controls whether the provided hash is in SHA-1 or NTLM format
	// HashMode defaults to SHA-1 and can be overridden using the WithNTLMHash() Option
	// See: https://haveibeenpwned.com/API/v3#PwnedPasswordsNTLM
	HashMode HashMode

	// WithPadding controls if the PwnedPassword API returns with padding or not
	// See: https://haveibeenpwned.com/API/v3#PwnedPasswordsPadding
	WithPadding bool
}

// CheckPassword checks the Pwned Passwords database against a given password string
//
// This method will automatically decide whether the hash is in SHA-1 or NTLM format based on
// the Option when the Client was initialized
func (p *PwnedPassAPI) CheckPassword(pw string) (Match, *http.Response, error) {
	switch p.hibp.PwnedPassAPIOpts.HashMode {
	case HashModeSHA1:
		shaSum := fmt.Sprintf("%x", sha1.Sum([]byte(pw)))
		return p.CheckSHA1(shaSum)
	case HashModeNTLM:
		d := md4.New()
		d.Write(stringToUTF16(pw))
		md4Sum := fmt.Sprintf("%x", d.Sum(nil))
		return p.CheckNTLM(md4Sum)
	default:
		return Match{}, nil, ErrUnsupportedHashMode
	}
}

// CheckSHA1 checks the Pwned Passwords database against a given SHA1 checksum of a password string
func (p *PwnedPassAPI) CheckSHA1(h string) (Match, *http.Response, error) {
	if len(h) != 40 {
		return Match{}, nil, ErrSHA1LengthMismatch
	}

	p.hibp.PwnedPassAPIOpts.HashMode = HashModeSHA1
	pwMatches, hr, err := p.ListHashesPrefix(h[:5])
	if err != nil {
		return Match{}, hr, err
	}

	for i := range pwMatches {
		match := pwMatches[i]
		if match.Hash == strings.ToLower(h) {
			match.present = true
			return match, hr, nil
		}
	}
	return Match{}, hr, nil
}

// CheckNTLM checks the Pwned Passwords database against a given NTLM hash of a password string
func (p *PwnedPassAPI) CheckNTLM(h string) (Match, *http.Response, error) {
	if len(h) != 32 {
		return Match{}, nil, ErrNTLMLengthMismatch
	}

	p.hibp.PwnedPassAPIOpts.HashMode = HashModeNTLM
	pwMatches, hr, err := p.ListHashesPrefix(h[:5])
	if err != nil {
		return Match{}, hr, err
	}

	for i := range pwMatches {
		match := pwMatches[i]
		if match.Hash == strings.ToLower(h) {
			match.present = true
			return match, hr, nil
		}
	}
	return Match{}, hr, nil
}

// ListHashesPassword checks the Pwned Password API endpoint for all hashes based on a given
// password string and returns the a slice of Match as well as the http.Response
//
// This method will automatically decide whether the hash is in SHA-1 or NTLM format based on
// the Option when the Client was initialized
//
// NOTE: If the `WithPwnedPadding` option is set to true, the returned list will be padded and might
// contain junk data
func (p *PwnedPassAPI) ListHashesPassword(pw string) ([]Match, *http.Response, error) {
	switch p.hibp.PwnedPassAPIOpts.HashMode {
	case HashModeSHA1:
		shaSum := fmt.Sprintf("%x", sha1.Sum([]byte(pw)))
		return p.ListHashesSHA1(shaSum)
	case HashModeNTLM:
		d := md4.New()
		d.Write(stringToUTF16(pw))
		md4Sum := fmt.Sprintf("%x", d.Sum(nil))
		return p.ListHashesNTLM(md4Sum)
	default:
		return nil, nil, ErrUnsupportedHashMode
	}
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
	p.hibp.PwnedPassAPIOpts.HashMode = HashModeSHA1
	dst := make([]byte, hex.DecodedLen(len(h)))
	if _, err := hex.Decode(dst, []byte(h)); err != nil {
		return nil, nil, ErrSHA1Invalid
	}
	return p.ListHashesPrefix(h[:5])
}

// ListHashesNTLM checks the Pwned Password API endpoint for all hashes based on a given
// NTLM hash and returns the a slice of Match as well as the http.Response
//
// NOTE: If the `WithPwnedPadding` option is set to true, the returned list will be padded and might
// contain junk data
func (p *PwnedPassAPI) ListHashesNTLM(h string) ([]Match, *http.Response, error) {
	if len(h) != 32 {
		return nil, nil, ErrNTLMLengthMismatch
	}
	p.hibp.PwnedPassAPIOpts.HashMode = HashModeNTLM
	dst := make([]byte, hex.DecodedLen(len(h)))
	if _, err := hex.Decode(dst, []byte(h)); err != nil {
		return nil, nil, ErrNTLMInvalid
	}
	return p.ListHashesPrefix(h[:5])
}

// ListHashesPrefix checks the Pwned Password API endpoint for all hashes based on a given
// SHA-1 or NTLM hash prefix and returns the a slice of Match as well as the http.Response
//
// To decide which HashType is queried for, make sure to set the appropriate HashMode in
// the PwnedPassAPI struct
//
// NOTE: If the `WithPwnedPadding` option is set to true, the returned list will be padded and might
// contain junk data
func (p *PwnedPassAPI) ListHashesPrefix(pf string) ([]Match, *http.Response, error) {
	if len(pf) != 5 {
		return nil, nil, ErrPrefixLengthMismatch
	}

	switch p.hibp.PwnedPassAPIOpts.HashMode {
	case HashModeSHA1:
		delete(p.ParamMap, "mode")
	case HashModeNTLM:
		p.ParamMap["mode"] = "ntlm"
	default:
		delete(p.ParamMap, "mode")
	}
	au := fmt.Sprintf("%s/range/%s", PasswdBaseURL, pf)
	hreq, err := p.hibp.HTTPReq(http.MethodGet, au, p.ParamMap)
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
		if len(hp) != 2 {
			continue
		}
		fh := fmt.Sprintf("%s%s", strings.ToLower(pf), strings.ToLower(hp[0]))
		hc, err := strconv.ParseInt(hp[1], 10, 64)
		if err != nil {
			continue
		}
		if hc == 0 {
			continue
		}
		pm = append(pm, Match{
			Hash:    fh,
			Count:   hc,
			present: true,
		})
	}

	if err = so.Err(); err != nil {
		return nil, hr, err
	}

	return pm, hr, nil
}

// stringToUTF16 converts a given string to a UTF-16 little-endian encoded byte slice
func stringToUTF16(s string) []byte {
	e := utf16.Encode([]rune(s))
	r := make([]byte, len(e)*2)
	for i := 0; i < len(e); i++ {
		r[i*2] = byte(e[i])
		r[i*2+1] = byte(e[i] << 8)
	}
	return r
}

// Present indicates whether the Match object has been returned by the HIBP API.
func (m Match) Present() bool {
	return m.present
}
