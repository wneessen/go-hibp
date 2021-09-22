package hibp

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

// Version represents the version of this package
const Version = "0.1.5"

// BaseUrl is the base URL for the majority of API calls
const BaseUrl = "https://haveibeenpwned.com/api/v3"

// DefaultUserAgent defines the default UA string for the HTTP client
// Currently the URL in the UA string is comment out, as there is a bug in the HIBP API
// not allowing multiple slashes
const DefaultUserAgent = `go-hibp v` + Version // + ` - https://github.com/wneessen/go-hibp`

// Client is the HIBP client object
type Client struct {
	hc *http.Client  // HTTP client to perform the API requests
	to time.Duration // HTTP client timeout
	ak string        // HIBP API key
	ua string        // User agent string for the HTTP client

	// If set to true, the HTTP client will sleep instead of failing in case the HTTP 429
	// rate limit hits a request
	rlSleep bool

	PwnedPassApi     *PwnedPassApi         // Reference to the PwnedPassApi API
	PwnedPassApiOpts *PwnedPasswordOptions // Additional options for the PwnedPassApi API

	BreachApi *BreachApi // Reference to the BreachApi API
}

// Option is a function that is used for grouping of Client options.
type Option func(*Client)

// New creates and returns a new HIBP client object
func New(options ...Option) Client {
	c := Client{}

	// Set defaults
	c.to = time.Second * 5
	c.PwnedPassApiOpts = &PwnedPasswordOptions{}
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
	c.PwnedPassApi = &PwnedPassApi{hibp: &c}
	c.BreachApi = &BreachApi{hibp: &c}

	return c
}

// WithHttpTimeout overrides the default http client timeout
func WithHttpTimeout(t time.Duration) Option {
	return func(c *Client) {
		c.to = t
	}
}

// WithApiKey set the optional API key to the Client object
func WithApiKey(k string) Option {
	return func(c *Client) {
		c.ak = k
	}
}

// WithPwnedPadding enables padding-mode for the PwnedPasswords API client
func WithPwnedPadding() Option {
	return func(c *Client) {
		c.PwnedPassApiOpts.WithPadding = true
	}
}

// WithUserAgent sets a custom user agent string for the HTTP client
func WithUserAgent(a string) Option {
	if a == "" {
		return func(c *Client) {}
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

// HttpReq performs an HTTP request to the corresponding API
func (c *Client) HttpReq(m, p string, q map[string]string) (*http.Request, error) {
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
	if c.PwnedPassApiOpts.WithPadding {
		hr.Header.Set("Add-Padding", "true")
	}

	return hr, nil
}

// HttpResBody performs the API call to the given path and returns the response body as byte array
func (c *Client) HttpResBody(m string, p string, q map[string]string) ([]byte, *http.Response, error) {
	hreq, err := c.HttpReq(m, p, q)
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
		log.Printf("API rate limit hit. Retrying request in %s", delayTime.String())
		time.Sleep(delayTime)
		return c.HttpResBody(m, p, q)
	}

	if hr.StatusCode != 200 {
		return nil, hr, fmt.Errorf("API responded with non HTTP-200: %s - %s", hr.Status, hb)
	}

	return hb, hr, nil
}

// httpClient returns a custom http client for the HIBP Client object
func httpClient(to time.Duration) *http.Client {
	tlsConfig := &tls.Config{
		MaxVersion: tls.VersionTLS13,
		MinVersion: tls.VersionTLS12,
	}
	httpTransport := &http.Transport{TLSClientConfig: tlsConfig}
	httpClient := &http.Client{
		Transport: httpTransport,
		Timeout:   5 * time.Second,
	}
	if to.Nanoseconds() > 0 {
		httpClient.Timeout = to
	}

	return httpClient
}
