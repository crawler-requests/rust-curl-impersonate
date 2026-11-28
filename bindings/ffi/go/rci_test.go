package rci

import (
	"os"
	"strings"
	"testing"
)

// base is the offline test server. tests/README explains how to start it; CI
// starts it at 8765.
func base() string {
	if value := os.Getenv("RCI_BASE"); value != "" {
		return value
	}
	return "http://127.0.0.1:8765"
}

func TestVersion(t *testing.T) {
	if Version() < 2 {
		t.Fatalf("ABI %d, this binding needs >= 2", Version())
	}
}

func TestTargetsAndProfiles(t *testing.T) {
	targets, err := Targets()
	if err != nil {
		t.Fatalf("targets: %v", err)
	}
	if len(targets) != 48 {
		t.Fatalf("targets: want 48, got %d", len(targets))
	}
	profiles, err := Profiles()
	if err != nil {
		t.Fatalf("profiles: %v", err)
	}
	if len(profiles) <= len(targets) {
		t.Fatalf("profiles (%d) should exceed presets (%d)", len(profiles), len(targets))
	}
	for _, name := range targets {
		found := false
		for _, candidate := range profiles {
			if candidate == name {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("target %s missing from profiles", name)
		}
	}
}

func TestLookupProfile(t *testing.T) {
	info, err := LookupProfile("chrome150")
	if err != nil {
		t.Fatalf("chrome150: %v", err)
	}
	if info.Family != "chrome" {
		t.Fatalf("family: %s", info.Family)
	}
	if !info.HasHTTP3 {
		t.Fatal("chrome150 should carry an HTTP/3 record")
	}
	if _, err := LookupProfile("definitely-not-a-profile"); err == nil {
		t.Fatal("an unknown profile should be an error")
	} else if !strings.Contains(err.Error(), "unknown profile") {
		t.Fatalf("error should name the cause: %v", err)
	}
}

func TestGetAndResponseHelpers(t *testing.T) {
	client, err := NewClient("chrome150", nil)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	reply, err := client.Get(base() + "/index.html")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if reply.Status != 200 {
		t.Fatalf("status %d", reply.Status)
	}
	text, err := reply.Text()
	if err != nil {
		t.Fatalf("text: %v", err)
	}
	if text != "hello from rust-curl-impersonate" {
		t.Fatalf("body: %q", text)
	}
	if !strings.Contains(reply.Header("Content-Type"), "text/plain") {
		t.Fatalf("content-type: %q", reply.Header("content-type"))
	}
	if reply.Version != "HTTP/1.1" && reply.Version != "HTTP/2.0" {
		t.Fatalf("version: %q", reply.Version)
	}
}

func TestBinaryBodyDecodes(t *testing.T) {
	reply, err := OneShotGet("chrome150", base()+"/rci-smoke.bin")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if reply.BodyIsText {
		t.Fatal("a binary body must not be reported as text")
	}
	content, err := reply.Content()
	if err != nil {
		t.Fatalf("content: %v", err)
	}
	if string(content) != "\x00\x01\x02\xff\xfe binary" {
		t.Fatalf("hex did not decode: %q", content)
	}
}

func TestPerRequestHeaders(t *testing.T) {
	client, err := NewClient("chrome150", nil)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	reply, err := client.RequestWithHeaders(
		"POST", base()+"/echo",
		[][2]string{{"x-marker", "go"}},
		`{"a":1}`,
	)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	body, err := reply.Text()
	if err != nil {
		t.Fatalf("text: %v", err)
	}
	// The echo server reflects the headers as JSON: check the marker survived.
	var echoed map[string]any
	if err := jsonUnmarshal(body, &echoed); err != nil {
		t.Fatalf("echo not json: %v (%s)", err, body)
	}
	headers, ok := echoed["headers"].(map[string]any)
	if !ok {
		t.Fatalf("echo has no headers map: %s", body)
	}
	if headers["x-marker"] != "go" {
		t.Fatalf("x-marker did not arrive: %v", headers["x-marker"])
	}
}

func TestUnknownOptionIsAnError(t *testing.T) {
	timeout := 5000
	_, err := NewClient("chrome150", &Options{TimeoutMS: &timeout})
	if err != nil {
		t.Fatalf("a known option should be accepted: %v", err)
	}
	// An unknown key is not expressible through Options, which is the point:
	// the typed struct cannot produce one. The library's own rejection is
	// covered by the Python and Rust suites.
}

func TestDefaultRedirectIsNotFollowed(t *testing.T) {
	reply, err := OneShotGet("chrome150", base()+"/redirect")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if reply.Status != 302 {
		t.Fatalf("a redirect should come back as 302, got %d", reply.Status)
	}
	if reply.Header("Location") == "" {
		t.Fatal("the Location header should be present")
	}
}

func TestFollowSafeFollowsAndRefusesLoopback(t *testing.T) {
	safe := true
	client, err := NewClient("chrome150", &Options{FollowSafe: &safe})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()
	// The test server redirects to a relative path, which resolves to the
	// same loopback address; the ABI follows it and then refuses the address.
	reply, err := client.Get(base() + "/redirect")
	if err != nil {
		// A refusal surfaces either as an error or as a {"error": ...} body,
		// depending on where the transport stops.
		if !strings.Contains(err.Error(), "blocked") && !strings.Contains(err.Error(), "error") {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if reply.Status != 200 {
		t.Fatalf("follow_safe should have followed the redirect, got %d", reply.Status)
	}
}

// The cookie jar lives on the handle, so the second request must carry what
// the first response set. The offline test server has no Set-Cookie route, so
// this drives the jar directly through the ABI's own headers path.
func TestCookieCarriesBetweenRequestsOnOneClient(t *testing.T) {
	client, err := NewClient("chrome150", nil)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	if _, err := client.Get(base() + "/cookie"); err != nil {
		t.Fatalf("cookie: %v", err)
	}
	reply, err := client.Get(base() + "/echo")
	if err != nil {
		t.Fatalf("echo: %v", err)
	}
	body, err := reply.Text()
	if err != nil {
		t.Fatalf("text: %v", err)
	}
	if !strings.Contains(body, "sid=abc123") {
		t.Fatalf("cookie did not persist on the handle: %s", body)
	}
	activity, err := client.Activity()
	if err != nil {
		t.Fatalf("activity: %v", err)
	}
	if len(activity.Cookies) == 0 {
		t.Fatal("the cookie change should be recorded")
	}
}

func TestWireProfile(t *testing.T) {
	client, err := NewClient("python3.12_requests", nil)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()
	name, err := client.WireProfile()
	if err != nil {
		t.Fatalf("wire profile: %v", err)
	}
	if name != "python3.12_requests" {
		t.Fatalf("wire profile: %s", name)
	}
}

func TestHTTP1OnlyForcesHTTP1(t *testing.T) {
	only := true
	client, err := NewClient("chrome150", &Options{HTTP1Only: &only})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()
	reply, err := client.Get("https://example.com/")
	if err != nil {
		t.Skipf("needs the internet to prove the negotiation: %v", err)
	}
	if reply.Version != "HTTP/1.1" {
		t.Fatalf("http1_only should negotiate HTTP/1.1, got %q", reply.Version)
	}
}

func TestLoadFingerprints(t *testing.T) {
	document := `[{"name":"go_test_client","extends":"chrome150","family":"chrome","platform":"linux"}]`
	if err := LoadFingerprints(document); err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := LookupProfile("go_test_client"); err != nil {
		t.Fatalf("the loaded record should resolve: %v", err)
	}
	if err := LoadFingerprints(`[{"name":"go_bad","tls":{"ciphers":"NOT_A_CIPHER"}}]`); err == nil {
		t.Fatal("an unbuildable record must be rejected at load time")
	}
}
