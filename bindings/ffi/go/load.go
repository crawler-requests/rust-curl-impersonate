//go:build cgo

package rci

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// LibraryName is the file name the C ABI ships under on this platform.
func LibraryName() string {
	switch runtime.GOOS {
	case "darwin":
		return "librust_curl_impersonate_ffi.dylib"
	case "windows":
		return "rust_curl_impersonate_ffi.dll"
	default:
		return "librust_curl_impersonate_ffi.so"
	}
}

// CandidateDirs lists the places Load looks in, in order. It covers both
// layouts the library ships in: the release archive (lib/ next to this
// package) and a `cargo build` inside the repository (target/release three
// directories up).
func CandidateDirs() []string {
	here, err := os.Getwd()
	if err != nil {
		here = "."
	}
	exe, err := os.Executable()
	if err != nil {
		exe = ""
	}
	dirs := []string{
		os.Getenv("RCI_LIB_DIR"),
		"lib",
		filepath.Join("..", "lib"),
		filepath.Join("python", "..", "lib"),
		filepath.Join("..", "..", "target", "release"),
		filepath.Join("..", "..", "..", "target", "release"),
		here,
	}
	if exe != "" {
		dirs = append(dirs, filepath.Join(filepath.Dir(exe), "lib"))
	}
	return dirs
}

// resolve returns the library path to load.
//
// RCI_LIB wins when set (a file or a directory); then RCI_LIB_DIR; then the
// candidate directories above.
func resolve(path string) (string, error) {
	name := LibraryName()
	if path != "" {
		return pathFrom(path, name)
	}
	if explicit := os.Getenv("RCI_LIB"); explicit != "" {
		return pathFrom(explicit, name)
	}
	for _, dir := range CandidateDirs() {
		candidate := filepath.Join(dir, name)
		if _, err := os.Stat(candidate); err == nil {
			absolute, err := filepath.Abs(candidate)
			if err != nil {
				return candidate, nil
			}
			return absolute, nil
		}
	}
	return "", fmt.Errorf(
		"%s not found; set RCI_LIB or RCI_LIB_DIR (looked in %v)", name, CandidateDirs(),
	)
}

func pathFrom(path, name string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("no shared library at %s: %w", path, err)
	}
	if info.IsDir() {
		path = filepath.Join(path, name)
		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("no %s in %s", name, filepath.Dir(path))
		}
	}
	return filepath.Abs(path)
}
