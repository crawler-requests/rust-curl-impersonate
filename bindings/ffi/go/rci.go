//go:build cgo

package rci

import "fmt"

// Version is rci_version: the ABI version the linked library reports.
func Version() int { return cVersion() }

func takeNames(text string) ([]string, error) {
	var names []string
	if err := jsonUnmarshal(text, &names); err != nil {
		return nil, fmt.Errorf("library returned a non-array: %w (%s)", err, text)
	}
	return names, nil
}

// Targets is the 48 curl-impersonate preset names.
func Targets() ([]string, error) { return takeNames(cTargets()) }

// Profiles is every selectable name: the 48 presets plus the fingerprint
// library's records.
func Profiles() ([]string, error) { return takeNames(cProfiles()) }

// ProfileInfo is the metadata rci_profile_info returns for a name.
type ProfileInfo struct {
	Name      string  `json:"name"`
	Wire      string  `json:"wire"`
	Family    string  `json:"family"`
	Platform  string  `json:"platform"`
	Fidelity  *string `json:"fidelity"`
	Deviation *string `json:"deviation"`
	HTTP1Only bool    `json:"http1_only"`
	HasHTTP3  bool    `json:"has_http3"`
	Source    string  `json:"source"`
}

// LookupProfile asks for one profile's metadata. Unknown names come back as the
// library's {"error": ...} object, which becomes a Go error.
func LookupProfile(name string) (*ProfileInfo, error) {
	text := cProfileInfo(name)
	var reply map[string]any
	if err := jsonUnmarshal(text, &reply); err != nil {
		return nil, fmt.Errorf("profile_info: %w (%s)", err, text)
	}
	if message, ok := reply["error"].(string); ok {
		return nil, fmt.Errorf("%s", message)
	}
	var info ProfileInfo
	if err := jsonUnmarshal(text, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// Response is one request's result, in the ABI's JSON shape.
type Response struct {
	Status     int         `json:"status"`
	Version    string      `json:"version"`
	URL        string      `json:"url"`
	Headers    [][2]string `json:"headers"`
	Body       string      `json:"body"`
	BodyIsText bool        `json:"body_is_text"`
}

// Text returns the body when the library decoded it as UTF-8.
func (r *Response) Text() (string, error) {
	if !r.BodyIsText {
		return "", fmt.Errorf("body is binary; call Content")
	}
	return r.Body, nil
}

// Header returns the first value for a name, case-insensitively.
func (r *Response) Header(name string) string {
	for _, pair := range r.Headers {
		if equalFold(pair[0], name) {
			return pair[1]
		}
	}
	return ""
}

// Content decodes the body: text as bytes when the library says so, otherwise
// the lowercase hex it uses for anything that is not UTF-8.
func (r *Response) Content() ([]byte, error) {
	if r.BodyIsText {
		return []byte(r.Body), nil
	}
	return hexDecode(r.Body)
}

// Client is one handle: a profile, a connection pool and a cookie jar.
// Calls block the calling goroutine until the response arrives. Close it with
// defer, exactly once.
type Client struct {
	handle  cHandle
	profile string
	freed   bool
}

// Options map to rci_client_new_with_options. Pass nil for the defaults.
// Unknown keys are rejected by the library, so a typo surfaces as an error
// from NewClient instead of a silently ignored setting.
type Options struct {
	TimeoutMS          *int
	Proxy              *string
	FollowRedirects    *bool
	FollowSafe         *bool
	PoolMaxIdlePerHost *int
	Headers            [][2]string
	SplitCookies       *bool
	HTTP1Only          *bool
}

func (o *Options) json() (string, error) {
	if o == nil {
		return "", nil
	}
	payload := map[string]any{}
	if o.TimeoutMS != nil {
		payload["timeout_ms"] = *o.TimeoutMS
	}
	if o.Proxy != nil {
		payload["proxy"] = *o.Proxy
	}
	if o.FollowRedirects != nil {
		payload["follow_redirects"] = *o.FollowRedirects
	}
	if o.FollowSafe != nil {
		payload["follow_safe"] = *o.FollowSafe
	}
	if o.PoolMaxIdlePerHost != nil {
		payload["pool_max_idle_per_host"] = *o.PoolMaxIdlePerHost
	}
	if len(o.Headers) > 0 {
		pairs := make([][2]string, len(o.Headers))
		copy(pairs, o.Headers)
		payload["headers"] = pairs
	}
	if o.SplitCookies != nil {
		payload["split_cookies"] = *o.SplitCookies
	}
	if o.HTTP1Only != nil {
		payload["http1_only"] = *o.HTTP1Only
	}
	if len(payload) == 0 {
		return "", nil
	}
	return jsonMarshal(payload)
}

// NewClient creates a handle. An unknown profile or an invalid option comes
// back as an error built from rci_last_error, which is where the library
// reports handle-construction failures.
func NewClient(profile string, options *Options) (*Client, error) {
	encoded, err := options.json()
	if err != nil {
		return nil, err
	}
	handle, message := cClientNew(profile, encoded)
	if handle == nil {
		if message == "" {
			message = "rci_client_new_with_options returned NULL"
		}
		return nil, fmt.Errorf("%s", message)
	}
	return &Client{handle: handle, profile: profile}, nil
}

// WireProfile is rci_client_profile: the preset whose bytes this handle sends.
func (c *Client) WireProfile() (string, error) {
	if err := c.check(); err != nil {
		return "", err
	}
	return cClientProfile(c.handle), nil
}

// Request sends one request with a byte body. `method` is sent verbatim: the
// ABI does not validate it, so a typo reaches the server (a 501) instead of
// failing here.
func (c *Client) Request(method, url string, body []byte) (*Response, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	return decodeResponse(cRequest(c.handle, method, url, body))
}

// RequestWithHeaders sends one request with per-request headers and a string
// body. It is the ABI's only per-request-header path, and its body is
// NUL-terminated, so the combination refuses binary bodies rather than
// truncating them.
func (c *Client) RequestWithHeaders(
	method, url string,
	headers [][2]string,
	body string,
) (*Response, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	headersJSON := ""
	if len(headers) > 0 {
		encoded, err := jsonMarshal(headers)
		if err != nil {
			return nil, err
		}
		headersJSON = encoded
	}
	return decodeResponse(cRequestWithHeaders(c.handle, method, url, headersJSON, body))
}

// Get is Request("GET", url, nil).
func (c *Client) Get(url string) (*Response, error) {
	return c.Request("GET", url, nil)
}

// Post is a UTF-8 body with no per-request headers.
func (c *Client) Post(url, body string) (*Response, error) {
	return c.RequestWithHeaders("POST", url, nil, body)
}

// LastHeaders is the most recent response's headers.
func (c *Client) LastHeaders() ([][2]string, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	text := cLastHeaders(c.handle)
	var pairs [][2]string
	if err := jsonUnmarshal(text, &pairs); err != nil {
		return nil, fmt.Errorf("last_headers: %w (%s)", err, text)
	}
	return pairs, nil
}

// Activity is what the handle recorded: cookie changes and redirect history.
type Activity struct {
	Cookies   []string `json:"cookies"`
	Redirects []string `json:"redirects"`
}

// Activity reads rci_client_activity.
func (c *Client) Activity() (*Activity, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	text := cActivity(c.handle)
	var activity Activity
	if err := jsonUnmarshal(text, &activity); err != nil {
		return nil, fmt.Errorf("activity: %w (%s)", err, text)
	}
	return &activity, nil
}

// Close releases the handle. Calling it twice is safe.
func (c *Client) Close() {
	if c == nil || c.freed || c.handle == nil {
		return
	}
	cClientFree(c.handle)
	c.freed = true
	c.handle = nil
}

func (c *Client) check() error {
	if c == nil || c.freed || c.handle == nil {
		return fmt.Errorf("rci: client is closed")
	}
	return nil
}

// OneShotGet is rci_get: it creates a handle, sends the GET and frees the
// handle. It keeps no cookie and no connection between calls; use NewClient
// and Client.Get for anything sent more than once.
func OneShotGet(profile, url string) (*Response, error) {
	return decodeResponse(cGet(profile, url))
}

// HTTP3Get is rci_http3_get. addr is "host:port" (a name is resolved first),
// host is the SNI and :authority, path is the request target. The profile must
// carry an HTTP/3 record; ProfileInfo.HasHTTP3 says whether it does.
func HTTP3Get(profile, addr, host, path string) (*Response, error) {
	return decodeResponse(cHTTP3Get(profile, addr, host, path))
}

// LoadFingerprints registers a library-schema JSON document for this process.
// A record it adds can shadow a built-in one of the same name until the
// process exits. The whole document is validated first, so success means the
// records can actually be sent.
func LoadFingerprints(document string) error {
	text := cLoadFingerprints(document)
	var reply map[string]any
	if err := jsonUnmarshal(text, &reply); err != nil {
		return fmt.Errorf("load_fingerprints: %w (%s)", err, text)
	}
	if message, ok := reply["error"].(string); ok {
		return fmt.Errorf("%s", message)
	}
	return nil
}

func decodeResponse(text string) (*Response, error) {
	var response Response
	if err := jsonUnmarshal(text, &response); err != nil {
		return nil, fmt.Errorf("library returned non-JSON: %w (%s)", err, text)
	}
	// A failed request still comes back as {"error": ...}; every other binding
	// turns that into an exception, and a Go caller checks err first.
	if message, ok := errorField(text); ok {
		return &response, fmt.Errorf("%s", message)
	}
	return &response, nil
}

// Load opens the library. With cgo the symbols are linked at build time, so it
// only confirms the ABI version; the path is used for the error message.
func Load(path string) error {
	resolved, err := resolve(path)
	if err != nil {
		return err
	}
	return loadAt(resolved)
}
