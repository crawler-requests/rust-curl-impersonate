// Capture the default Go net/http fingerprint by asking tls.peet.ws to echo
// the ClientHello and HTTP/2 frames it received.
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	out := os.Args[1]
	transport := &http.Transport{ForceAttemptHTTP2: true}
	if len(os.Args) > 2 && os.Args[2] == "http1" {
		transport.ForceAttemptHTTP2 = false
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	client := &http.Client{Timeout: 20 * time.Second, Transport: transport}
	resp, err := client.Get("https://tls.peet.ws/api/all")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(out, body, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("go: %s %s\n", resp.Proto, resp.Status)
}
