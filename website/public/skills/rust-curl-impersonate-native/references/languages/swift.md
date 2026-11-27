# Swift / iOS / macOS

Not run on this machine (no Swift toolchain), but the packaging rule is hard.

## Which artifact

- **iOS app**: the **static** `.a`. App Store review rejects an app that ships
  a loose dynamic library, and a `.dylib` inside an app bundle is not signed
  the way the app expects. Use `aarch64-apple-ios` for a device,
  `aarch64-apple-ios-sim` / `x86_64-apple-ios` for simulators.
- **macOS app or CLI**: either the `.dylib` (`x86_64-apple-darwin` /
  `aarch64-apple-darwin`) or the static `.a`. A universal binary needs the
  two macOS archives.

```sh
python3 scripts/fetch_library.py --target aarch64-apple-ios --dest rci-ios
```

## Bridging header

Create `Rci-Bridging-Header.h`:

```c
#include "rci.h"
```

Swift imports the C declarations automatically:

```swift
print("abi \(rci_version())")

guard let client = rci_client_new("chrome150") else {
    print("error: \(String(cString: rci_last_error()))")
    exit(1)
}
defer { rci_client_free(client) }

if let reply = rci_get("chrome150", "https://tls.peet.ws/api/all") {
    defer { rci_string_free(reply) }
    print(String(cString: reply))
}
```

## Linking the static archive in Xcode

- Add `librust_curl_impersonate_ffi.a` to *Link Binary With Libraries*.
- The archive is C++, so the target's C++ runtime must be linked:
  add `libc++.tbd` (and `libz.tbd` if compression is unresolved).
- `OTHER_LDFLAGS` may need `-lc++`.

## Ownership

`char *` results are `UnsafeMutablePointer<CChar>?` in Swift. Read with
`String(cString:)`, then call `rci_string_free`. Never let ARC-style thinking
free them with `free()` — that is the wrong allocator.
