// Capture a uTLS ClientHello against tls.peet.ws over HTTP/1.1.
//
// uTLS only shapes the TLS handshake; the HTTP/2 fingerprint would come from
// whatever Go HTTP/2 stack the caller pairs it with, so these records keep the
// transport on HTTP/1.1 and describe the TLS ClientHello only. The ALPN list is
// narrowed to http/1.1 for the same reason.
//
// Usage: utlscap <output> <profile>
package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	utls "github.com/refraction-networking/utls"
)

type profile struct {
	id     utls.ClientHelloID
	family string
	ua     string
}

var profiles = map[string]profile{
	"chrome58":         {utls.HelloChrome_58, "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"},
	"chrome62":         {utls.HelloChrome_62, "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36"},
	"chrome70":         {utls.HelloChrome_70, "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36"},
	"chrome72":         {utls.HelloChrome_72, "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36"},
	"chrome83":         {utls.HelloChrome_83, "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"},
	"chrome87":         {utls.HelloChrome_87, "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"},
	"chrome96":         {utls.HelloChrome_96, "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"},
	"chrome100":        {utls.HelloChrome_100, "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"},
	"chrome102":        {utls.HelloChrome_102, "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36"},
	"chrome106shuffle": {utls.HelloChrome_106_Shuffle, "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.119 Safari/537.36"},
	"chrome115pq":      {utls.HelloChrome_115_PQ, "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.170 Safari/537.36"},
	"chrome120":        {utls.HelloChrome_120, "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
	"chrome120pq":      {utls.HelloChrome_120_PQ, "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
	"chrome131":        {utls.HelloChrome_131, "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
	"chrome133":        {utls.HelloChrome_133, "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"},
	"firefox55":        {utls.HelloFirefox_55, "firefox", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0"},
	"firefox56":        {utls.HelloFirefox_56, "firefox", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0"},
	"firefox63":        {utls.HelloFirefox_63, "firefox", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:63.0) Gecko/20100101 Firefox/63.0"},
	"firefox65":        {utls.HelloFirefox_65, "firefox", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:65.0) Gecko/20100101 Firefox/65.0"},
	"firefox99":        {utls.HelloFirefox_99, "firefox", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0"},
	"firefox102":       {utls.HelloFirefox_102, "firefox", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"},
	"firefox105":       {utls.HelloFirefox_105, "firefox", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0"},
	"firefox120":       {utls.HelloFirefox_120, "firefox", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"},
	"safari16":         {utls.HelloSafari_16_0, "safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"},
	"ios11":            {utls.HelloIOS_11_1, "ios", "Mozilla/5.0 (iPhone; CPU iPhone OS 11_1 like Mac OS X) AppleWebKit/604.3.5 (KHTML, like Gecko) Version/11.0 Mobile/15B93 Safari/604.1"},
	"ios12":            {utls.HelloIOS_12_1, "ios", "Mozilla/5.0 (iPhone; CPU iPhone OS 12_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1"},
	"ios13":            {utls.HelloIOS_13, "ios", "Mozilla/5.0 (iPhone; CPU iPhone OS 13_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0 Mobile/15E148 Safari/604.1"},
	"ios14":            {utls.HelloIOS_14, "ios", "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"},
	"android11okhttp":  {utls.HelloAndroid_11_OkHttp, "okhttp", "okhttp/4.9.1"},
	"edge85":           {utls.HelloEdge_85, "edge", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36 Edg/85.0.564.44"},
	"edge106":          {utls.HelloEdge_106, "edge", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36 Edg/106.0.1370.47"},
	"360_7_5":          {utls.Hello360_7_5, "360", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36 QIHU 360SE"},
	"360_11_0":         {utls.Hello360_11_0, "360", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36 QIHU 360SE"},
	"qq11_1":           {utls.HelloQQ_11_1, "qq", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.25 Safari/537.36 Core/1.70.3877.400 QQBrowser/10.8.4506.400"},
}

// narrowALPN keeps h2/h3 out of the ClientHello so the raw socket can speak
// HTTP/1.1 and the capture stays a TLS fingerprint, not a Go HTTP/2 one.
func narrowALPN(spec *utls.ClientHelloSpec) {
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
			return
		}
	}
	spec.Extensions = append(spec.Extensions, &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}})
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: utlscap <output> <profile>")
		os.Exit(2)
	}
	out, name := os.Args[1], os.Args[2]
	entry, ok := profiles[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown profile %q\n", name)
		os.Exit(2)
	}
	spec, err := utls.UTLSIdToSpec(entry.id)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	narrowALPN(&spec)

	conn, err := net.Dial("tcp", "tls.peet.ws:443")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer conn.Close()
	config := &utls.Config{ServerName: "tls.peet.ws"}
	uconn := utls.UClient(conn, config, utls.HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := uconn.Handshake(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	request := "GET /api/all HTTP/1.1\r\n" +
		"Host: tls.peet.ws\r\n" +
		"User-Agent: " + entry.ua + "\r\n" +
		"Accept: */*\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := io.WriteString(uconn, request); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	resp, err := http.ReadResponse(bufio.NewReader(uconn), nil)
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
	// tls.peet.ws answers JSON; reject an HTML error page so a stale body never
	// gets turned into a fingerprint.
	if !strings.HasPrefix(strings.TrimSpace(string(body)), "{") {
		fmt.Fprintf(os.Stderr, "%s: response is not JSON (%d bytes)\n", name, len(body))
		os.Exit(1)
	}
	if err := os.WriteFile(out, body, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("%s: saved %d bytes (status %d)\n", name, len(body), resp.StatusCode)
}
