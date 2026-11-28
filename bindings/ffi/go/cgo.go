//go:build cgo

// Package rci is a Go binding for the rust-curl-impersonate C ABI (ABI v2).
//
// The library is linked at build time by cgo; the process needs to find it at
// run time (rpath / LD_LIBRARY_PATH / beside the executable). Build with:
//
//	CGO_LDFLAGS="-L/path/to/lib -lrust_curl_impersonate_ffi -Wl,-rpath,/path/to/lib"
//
// Then:
//
//	info, err := rci.LookupProfile("chrome150")
//	client, err := rci.NewClient("chrome150", nil)
//	defer client.Close()
//	reply, err := client.Get("https://tls.peet.ws/api/all")
//
// Every returned string is owned by the library and freed with
// rci_string_free, which this binding does for you. One Client shares its
// cookie jar and connection pool across goroutines (the ABI serializes its own
// runtime, exercised with eight goroutines); one Client per goroutine keeps
// pools separate.
package rci

/*
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct RciClient RciClient;

extern uint32_t rci_version(void);
extern char *rci_targets(void);
extern char *rci_profiles(void);
extern char *rci_profile_info(const char * profile);
extern RciClient *rci_client_new(const char * profile);
extern RciClient *rci_client_new_with_options(const char * profile, const char * options_json);
extern void rci_client_free(RciClient * handle);
extern char *rci_client_profile(RciClient * handle);
extern char *rci_request(RciClient * handle, const char * method, const char * url, const uint8_t * body, size_t body_len);
extern char *rci_request_with(RciClient * handle, const char * method, const char * url, const char * headers_json, const char * body);
extern char *rci_get(const char * profile, const char * url);
extern char *rci_http3_get(const char * profile, const char * addr, const char * host, const char * path);
extern char *rci_client_last_headers(RciClient * handle);
extern char *rci_client_activity(RciClient * handle);
extern const char *rci_last_error(void);
extern char *rci_load_fingerprints(const char * json);
extern void rci_string_free(char * text);
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

// The C types stay in this file. Everything the public API needs is re-exported
// under a Go name so the rest of the package never mentions C — cgo's `import
// "C"` is per-file, and keeping it to one file is what lets the other files be
// ordinary Go.
type (
	cHandle = *C.RciClient
	cChar   = *C.char
	cByte   = *C.uint8_t
	cSize   = C.size_t
)

// takeString reads a NUL-terminated string the library returned and releases it.
// Every `char *` result belongs to the library; this is the only correct way to
// free it. Declaring the return as *C.char and calling C.GoString copies the
// bytes, and this then releases the original.
func takeString(pointer cChar) string {
	if pointer == nil {
		return ""
	}
	text := C.GoString(pointer)
	C.rci_string_free(pointer)
	return text
}

// lastError reads rci_last_error, which is borrowed: never freed.
func lastError() string {
	return C.GoString(C.rci_last_error())
}

// cstring returns a NUL-terminated copy of `text` and a function that releases
// it. An empty string becomes a NULL pointer, which the ABI reads as "not set"
// for options, headers and bodies.
func cstring(text string) (cChar, func()) {
	if text == "" {
		return nil, func() {}
	}
	pointer := C.CString(text)
	return pointer, func() { C.free(unsafe.Pointer(pointer)) }
}

func cVersion() int {
	return int(C.rci_version())
}

func cTargets() string  { return takeString(C.rci_targets()) }
func cProfiles() string { return takeString(C.rci_profiles()) }

func cProfileInfo(name string) string {
	pointer, done := cstring(name)
	defer done()
	return takeString(C.rci_profile_info(pointer))
}

func cClientNew(profile, options string) (cHandle, string) {
	pointer, done := cstring(profile)
	defer done()
	encoded, doneOptions := cstring(options)
	defer doneOptions()
	handle := C.rci_client_new_with_options(pointer, encoded)
	if handle == nil {
		return nil, lastError()
	}
	return handle, ""
}

func cClientFree(handle cHandle) {
	C.rci_client_free(handle)
}

func cClientProfile(handle cHandle) string {
	return takeString(C.rci_client_profile(handle))
}

// cRequest sends a byte body, held alive until the C call returns.
func cRequest(handle cHandle, method, url string, body []byte) string {
	name, doneName := cstring(method)
	defer doneName()
	target, doneTarget := cstring(url)
	defer doneTarget()

	var bodyPointer cByte
	var length cSize
	if len(body) > 0 {
		buffer := make([]byte, len(body))
		copy(buffer, body)
		bodyPointer = (cByte)(unsafe.Pointer(&buffer[0]))
		length = cSize(len(body))
		defer runtime.KeepAlive(buffer)
	}
	return takeString(C.rci_request(handle, name, target, bodyPointer, length))
}

func cRequestWithHeaders(handle cHandle, method, url, headersJSON, body string) string {
	name, doneName := cstring(method)
	defer doneName()
	target, doneTarget := cstring(url)
	defer doneTarget()
	headers, doneHeaders := cstring(headersJSON)
	defer doneHeaders()
	payload, doneBody := cstring(body)
	defer doneBody()
	return takeString(C.rci_request_with(handle, name, target, headers, payload))
}

func cGet(profile, url string) string {
	pointer, done := cstring(profile)
	defer done()
	target, doneTarget := cstring(url)
	defer doneTarget()
	return takeString(C.rci_get(pointer, target))
}

func cHTTP3Get(profile, addr, host, path string) string {
	name, doneName := cstring(profile)
	defer doneName()
	address, doneAddress := cstring(addr)
	defer doneAddress()
	authority, doneAuthority := cstring(host)
	defer doneAuthority()
	resource, doneResource := cstring(path)
	defer doneResource()
	return takeString(C.rci_http3_get(name, address, authority, resource))
}

func cLastHeaders(handle cHandle) string { return takeString(C.rci_client_last_headers(handle)) }
func cActivity(handle cHandle) string    { return takeString(C.rci_client_activity(handle)) }

func cLoadFingerprints(document string) string {
	pointer, done := cstring(document)
	defer done()
	return takeString(C.rci_load_fingerprints(pointer))
}

// loadAt is Load for the cgo build: the symbols are linked at build time, so
// there is nothing to open. It only confirms the library is the expected ABI.
func loadAt(path string) error {
	if cVersion() < 2 {
		return fmt.Errorf("library at %s reports ABI %d, this binding needs >= 2", path, cVersion())
	}
	return nil
}
