//go:build cgo

package rci

// The two JSON helpers and the case-insensitive header match. They exist so
// the binding carries no third-party dependency: the C ABI's payloads are
// fixed shapes, and encoding/json is in the standard library.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

func jsonMarshal(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode request payload: %w", err)
	}
	return string(encoded), nil
}

func jsonUnmarshal(text string, target any) error {
	return json.Unmarshal([]byte(text), target)
}

func equalFold(a, b string) bool {
	return strings.EqualFold(a, b)
}

func hexDecode(text string) ([]byte, error) {
	decoded, err := hex.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("decode binary body: %w", err)
	}
	return decoded, nil
}

// errorField reports whether the reply is the ABI's {"error": ...} object.
func errorField(text string) (string, bool) {
	var probe struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(text), &probe); err != nil {
		return "", false
	}
	if probe.Error == "" {
		return "", false
	}
	return probe.Error, true
}
