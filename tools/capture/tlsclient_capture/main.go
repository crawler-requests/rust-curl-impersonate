// Capture a tls-client profile against tls.peet.ws.
// Usage: tlsclientcap <output> <profile>
package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

// Representative request headers for each profile. tls-client only supplies
// the TLS and HTTP/2 shape, so without these the capture would record Go's
// default User-Agent.
func headersFor(name string) map[string]string {
	chrome := func(version string) map[string]string {
		return map[string]string{
			"user-agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + version + ".0.0.0 Safari/537.36",
			"accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
			"accept-language": "en-US,en;q=0.9",
			"accept-encoding": "gzip, deflate, br, zstd",
		}
	}
	safari := func(version string) map[string]string {
		return map[string]string{
			"user-agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/" + version + " Safari/605.1.15",
			"accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"accept-language": "en-US,en;q=0.9",
			"accept-encoding": "gzip, deflate, br",
		}
	}
	iosSafari := func(version string) map[string]string {
		return map[string]string{
			"user-agent":      "Mozilla/5.0 (iPhone; CPU iPhone OS " + strings.ReplaceAll(version, ".", "_") + " like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/" + version + " Mobile/15E148 Safari/604.1",
			"accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"accept-language": "en-US,en;q=0.9",
			"accept-encoding": "gzip, deflate, br",
		}
	}
	iosApp := map[string]string{
		"user-agent":      "CFNetwork/1474 Darwin/23.0.0",
		"accept":          "*/*",
		"accept-language": "en-US,en;q=0.9",
		"accept-encoding": "gzip, deflate, br",
	}
	androidApp := map[string]string{
		"user-agent":      "okhttp/4.12.0",
		"accept":          "*/*",
		"accept-encoding": "gzip, deflate, br",
	}

	switch {
	case strings.HasPrefix(name, "chrome"):
		return chrome(strings.TrimPrefix(name, "chrome"))
	case name == "brave146":
		return chrome("146")
	case name == "cloudflare":
		return chrome("146")
	case strings.HasPrefix(name, "firefox"):
		version := strings.TrimPrefix(name, "firefox")
		return map[string]string{
			"user-agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:" + version + ".0) Gecko/20100101 Firefox/" + version + ".0",
			"accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"accept-language": "en-US,en;q=0.5",
			"accept-encoding": "gzip, deflate, br, zstd",
		}
	case strings.HasPrefix(name, "opera"):
		version := strings.TrimPrefix(name, "opera")
		return map[string]string{
			"user-agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 OPR/" + version + ".0.0.0",
			"accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"accept-language": "en-US,en;q=0.9",
			"accept-encoding": "gzip, deflate, br, zstd",
		}
	case strings.HasPrefix(name, "ios_safari"):
		version := strings.TrimPrefix(name, "ios_safari")
		version = strings.ReplaceAll(version, "_", ".")
		if version == "16" || version == "17" || version == "18" {
			version += ".0"
		}
		return iosSafari(version)
	case strings.HasPrefix(name, "safari_ipad"):
		return iosApp
	case strings.HasPrefix(name, "safari"):
		return safari(strings.ReplaceAll(strings.TrimPrefix(name, "safari"), "_", "."))
	case strings.HasPrefix(name, "ios_"),
		strings.HasPrefix(name, "mms_ios"),
		strings.HasPrefix(name, "mesh_ios"),
		strings.HasSuffix(name, "_ios"):
		return iosApp
	default: // Android app and OkHttp profiles
		return androidApp
	}
}

var profileTable = map[string]profiles.ClientProfile{
	"android_confirmed":  profiles.ConfirmedAndroid,
	"android_confirmed2": profiles.ConfirmedAndroid2,
	"android_mesh":       profiles.MeshAndroid,
	"android_mesh1":      profiles.MeshAndroid2,
	"android_nike":       profiles.NikeAndroidMobile,
	"android_okhttp10":   profiles.Okhttp4Android10,
	"android_okhttp11":   profiles.Okhttp4Android11,
	"android_okhttp12":   profiles.Okhttp4Android12,
	"android_okhttp13":   profiles.Okhttp4Android13,
	"android_okhttp7":    profiles.Okhttp4Android7,
	"android_okhttp8":    profiles.Okhttp4Android8,
	"android_okhttp9":    profiles.Okhttp4Android9,
	"android_zalando":    profiles.ZalandoAndroidMobile,
	"brave146":           profiles.Brave_146,
	"chrome103":          profiles.Chrome_103,
	"chrome104":          profiles.Chrome_104,
	"chrome105":          profiles.Chrome_105,
	"chrome106":          profiles.Chrome_106,
	"chrome107":          profiles.Chrome_107,
	"chrome108":          profiles.Chrome_108,
	"chrome109":          profiles.Chrome_109,
	"chrome110":          profiles.Chrome_110,
	"chrome111":          profiles.Chrome_111,
	"chrome112":          profiles.Chrome_112,
	"chrome117":          profiles.Chrome_117,
	"chrome120":          profiles.Chrome_120,
	"chrome124":          profiles.Chrome_124,
	"chrome131":          profiles.Chrome_131,
	"chrome133":          profiles.Chrome_133,
	"chrome144":          profiles.Chrome_144,
	"chrome146":          profiles.Chrome_146,
	"chrome150":          profiles.Chrome_150,
	"chrome152":          profiles.Chrome_152,
	"cloudflare":         profiles.CloudflareCustom,
	"firefox102":         profiles.Firefox_102,
	"firefox104":         profiles.Firefox_104,
	"firefox105":         profiles.Firefox_105,
	"firefox106":         profiles.Firefox_106,
	"firefox108":         profiles.Firefox_108,
	"firefox110":         profiles.Firefox_110,
	"firefox117":         profiles.Firefox_117,
	"firefox120":         profiles.Firefox_120,
	"firefox123":         profiles.Firefox_123,
	"firefox132":         profiles.Firefox_132,
	"firefox133":         profiles.Firefox_133,
	"firefox135":         profiles.Firefox_135,
	"firefox147":         profiles.Firefox_147,
	"firefox148":         profiles.Firefox_148,
	"ios_confirmed":      profiles.ConfirmedIos,
	"ios_mms":            profiles.MMSIos,
	"ios_mms2":           profiles.MMSIos2,
	"ios_mms3":           profiles.MMSIos3,
	"ios_mesh":           profiles.MeshIos,
	"ios_mesh2":          profiles.MeshIos2,
	"ios_nike":           profiles.NikeIosMobile,
	"ios_safari15_5":     profiles.Safari_IOS_15_5,
	"ios_safari15_6":     profiles.Safari_IOS_15_6,
	"ios_safari16":       profiles.Safari_IOS_16_0,
	"ios_safari17":       profiles.Safari_IOS_17_0,
	"ios_safari18":       profiles.Safari_IOS_18_0,
	"ios_safari18_5":     profiles.Safari_IOS_18_5,
	"ios_safari26":       profiles.Safari_IOS_26_0,
	"ios_zalando":        profiles.ZalandoIosMobile,
	"opera89":            profiles.Opera_89,
	"opera90":            profiles.Opera_90,
	"opera91":            profiles.Opera_91,
	"safari15_6_1":       profiles.Safari_15_6_1,
	"safari16":           profiles.Safari_16_0,
	"safari_ipad15_6":    profiles.Safari_Ipad_15_6,
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: tlsclientcap <output> <profile>")
		os.Exit(2)
	}
	out, name := os.Args[1], os.Args[2]
	profile, ok := profileTable[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown profile %q\n", name)
		os.Exit(2)
	}
	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(),
		tls_client.WithTimeoutSeconds(30),
		tls_client.WithClientProfile(profile))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	req, err := fhttp.NewRequest("GET", "https://tls.peet.ws/api/all", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for key, value := range headersFor(name) {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
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
	fmt.Printf("%s: saved %d bytes (status %d)\n", name, len(body), resp.StatusCode)
}
