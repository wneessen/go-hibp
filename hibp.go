// Package hibp provides Go binding to all 3 APIs of the "Have I Been Pwned" by Troy Hunt
package hibp

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Version represents the version of this package
const Version = "1.0.5"

// BaseURL is the base URL for the majority of API endpoints
const BaseURL = "https://haveibeenpwned.com/api/v3"

// PasswdBaseURL is the base URL for the pwned passwords API endpoints
const PasswdBaseURL = "https://api.pwnedpasswords.com"

// DefaultUserAgent defines the default UA string for the HTTP client
// Currently the URL in the UA string is comment out, as there is a bug in the HIBP API
// not allowing multiple slashes
const DefaultUserAgent = `go-hibp/` + Version + ` (+https://github.com/wneessen/go-hibp)`

// DefaultTimeout is the default timeout value for the HTTP client
const DefaultTimeout = time.Second * 5

// List of common errors
var (
	// ErrNoAccountID is returned if no account ID is given to the corresponding API method
	ErrNoAccountID = errors.New("no account ID given")

	// ErrNoName is returned if no name is given to the corresponding API method
	ErrNoName = errors.New("no name given")

	// ErrNonPositiveResponse should be returned if a HTTP request failed with a non HTTP-200 status
	ErrNonPositiveResponse = errors.New("non HTTP-200 response for HTTP request")

	// ErrPrefixLengthMismatch should be used if a given prefix does not match the
	// expected length
	ErrPrefixLengthMismatch = errors.New("password hash prefix must be 5 characters long")

	// ErrSHA1LengthMismatch should be used if a given SHA1 checksum does not match the
	// expected length
	ErrSHA1LengthMismatch = errors.New("SHA1 hash size needs to be 160 bits")

	// ErrNTLMLengthMismatch should be used if a given NTLM hash does not match the
	// expected length
	ErrNTLMLengthMismatch = errors.New("NTLM hash size needs to be 128 bits")

	// ErrSHA1Invalid should be used if a given string does not represent a valid SHA1 hash
	ErrSHA1Invalid = errors.New("not a valid SHA1 hash")

	// ErrNTLMInvalid should be used if a given string does not represent a valid NTLM hash
	ErrNTLMInvalid = errors.New("not a valid NTLM hash")

	// ErrUnsupportedHashMode should be used if a given hash mode is not supported
	ErrUnsupportedHashMode = errors.New("hash mode not supported")
)

// Client is the HIBP client object
type Client struct {
	hc *http.Client  // HTTP client to perform the API requests
	to time.Duration // HTTP client timeout
	ak string        // HIBP API key
	ua string        // User agent string for the HTTP client

	// If set to true, the HTTP client will sleep instead of failing in case the HTTP 429
	// rate limit hits a request
	rlSleep bool
	logger  io.Writer // The custom logger.

	PwnedPassAPI     *PwnedPassAPI         // Reference to the PwnedPassAPI API
	PwnedPassAPIOpts *PwnedPasswordOptions // Additional options for the PwnedPassAPI API

	BreachAPI *BreachAPI // Reference to the BreachAPI
	PasteAPI  *PasteAPI  // Reference to the PasteAPI
}

// Option is a function that is used for grouping of Client options.
type Option func(*Client)

// New creates and returns a new HIBP client object
func New(options ...Option) Client {
	c := Client{}

	// Set defaults
	c.to = DefaultTimeout
	c.PwnedPassAPIOpts = &PwnedPasswordOptions{
		HashMode:    HashModeSHA1,
		WithPadding: false,
	}
	c.ua = DefaultUserAgent

	// Set additional options
	for _, opt := range options {
		if opt == nil {
			continue
		}
		opt(&c)
	}

	// Add a http client to the Client object
	c.hc = httpClient(c.to)

	// Associate the different HIBP service APIs with the Client
	c.PwnedPassAPI = &PwnedPassAPI{
		hibp:     &c,
		ParamMap: make(map[string]string),
	}
	c.BreachAPI = &BreachAPI{hibp: &c}
	c.PasteAPI = &PasteAPI{hibp: &c}

	return c
}

// WithHTTPTimeout overrides the default http client timeout
func WithHTTPTimeout(t time.Duration) Option {
	return func(c *Client) {
		c.to = t
	}
}

// WithAPIKey set the optional API key to the Client object
func WithAPIKey(k string) Option {
	return func(c *Client) {
		c.ak = k
	}
}

// WithPwnedPadding enables padding-mode for the PwnedPasswords API client
func WithPwnedPadding() Option {
	return func(c *Client) {
		c.PwnedPassAPIOpts.WithPadding = true
	}
}

// WithUserAgent sets a custom user agent string for the HTTP client
func WithUserAgent(a string) Option {
	if a == "" {
		return nil
	}
	return func(c *Client) {
		c.ua = a
	}
}

// WithRateLimitSleep let's the HTTP client sleep in case the API rate limiting hits (Defaults to fail)
func WithRateLimitSleep() Option {
	return func(c *Client) {
		c.rlSleep = true
	}
}

// WithPwnedNTLMHash sets the hash mode for the PwnedPasswords API to NTLM hashes
//
// Note: This option only affects the generic methods like PwnedPassAPI.CheckPassword
// or PwnedPassAPI.ListHashesPassword. For any specifc method with the hash type in
// the method name, this option is ignored and the hash type of the function is
// forced
func WithPwnedNTLMHash() Option {
	return func(c *Client) {
		c.PwnedPassAPIOpts.HashMode = HashModeNTLM
	}
}

// WithLogger sets the logger.
func WithLogger(w io.Writer) Option {
	return func(c *Client) {
		c.logger = w
	}
}

// HTTPReq performs an HTTP request to the corresponding API
func (c *Client) HTTPReq(m, p string, q map[string]string) (*http.Request, error) {
	u, err := url.Parse(p)
	if err != nil {
		return nil, err
	}

	if m == http.MethodGet {
		uq := u.Query()
		for k, v := range q {
			uq.Add(k, v)
		}
		u.RawQuery = uq.Encode()
	}

	hr, err := http.NewRequest(m, u.String(), nil)
	if err != nil {
		return nil, err
	}

	if m == http.MethodPost {
		pd := url.Values{}
		for k, v := range q {
			pd.Add(k, v)
		}

		rb := io.NopCloser(bytes.NewBufferString(pd.Encode()))
		hr.Body = rb
	}

	hr.Header.Set("Accept", "application/json")
	hr.Header.Set("user-agent", c.ua)
	if c.ak != "" {
		hr.Header.Set("hibp-api-key", c.ak)
	}
	if c.PwnedPassAPIOpts.WithPadding {
		hr.Header.Set("Add-Padding", "true")
	}

	return hr, nil
}

// HTTPResBody performs the API call to the given path and returns the response body as byte array
func (c *Client) HTTPResBody(m string, p string, q map[string]string) ([]byte, *http.Response, error) {
	hreq, err := c.HTTPReq(m, p, q)
	if err != nil {
		return nil, nil, err
	}
	hr, err := c.hc.Do(hreq)
	if err != nil {
		return nil, hr, err
	}
	defer func() {
		_ = hr.Body.Close()
	}()

	hb, err := io.ReadAll(hr.Body)
	if err != nil {
		return nil, hr, err
	}

	if hr.StatusCode == 429 && c.rlSleep {
		headerDelay := hr.Header.Get("Retry-After")
		delayTime, err := time.ParseDuration(headerDelay + "s")
		if err != nil {
			return nil, hr, err
		}
		if c.logger != nil {
			c.logger.Write([]byte(fmt.Sprintf("API rate limit hit. Retrying request in %s\n", delayTime.String())))
		}
		time.Sleep(delayTime)
		return c.HTTPResBody(m, p, q)
	}

	if hr.StatusCode != 200 {
		return nil, hr, fmt.Errorf("HTTP %s: %w", hr.Status, ErrNonPositiveResponse)
	}

	return hb, hr, nil
}

// httpClient returns a custom http client for the HIBP Client object
func httpClient(to time.Duration) *http.Client {
	tc := &tls.Config{
		MaxVersion: tls.VersionTLS13,
		MinVersion: tls.VersionTLS12,
	}
	ht := &http.Transport{TLSClientConfig: tc}
	hc := &http.Client{
		Transport: ht,
		Timeout:   DefaultTimeout,
	}
	if to.Nanoseconds() > 0 {
		hc.Timeout = to
	}

	return hc
}
