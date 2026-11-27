# C# / .NET

Not run on this machine (no .NET toolchain), but the pattern is fixed by the
ABI. The one non-obvious rule: strings are UTF-8, so every `char *` argument
needs `LPUTF8Str`.

```csharp
using System;
using System.Runtime.InteropServices;

static class Rci {
    [DllImport("rust_curl_impersonate_ffi")]
    static extern uint rci_version();

    [DllImport("rust_curl_impersonate_ffi")]
    static extern IntPtr rci_get(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string profile,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string url);

    [DllImport("rust_curl_impersonate_ffi")]
    static extern void rci_string_free(IntPtr text);

    public static void Main() {
        Console.WriteLine($"abi {rci_version()}");
        IntPtr pointer = rci_get("chrome150", "https://example.com");
        try {
            Console.WriteLine(Marshal.PtrToStringUTF8(pointer));
        } finally {
            rci_string_free(pointer);
        }
    }
}
```

Rules:

- Return type is `IntPtr` (the library owns the string). Do **not** declare it
  `string` — the marshaller copies and discards the pointer, and the free call
  then releases memory the library never handed out.
- Free with `rci_string_free`; read with `Marshal.PtrToStringUTF8`.
- `rci_last_error` may be declared `string` (borrowed, not freed).
- Windows finds the `.dll` next to the `.exe`; elsewhere use an absolute path
  in `DllImport` or set the loader path.

Binary bodies: `reply.body_is_text == false` → decode the hex string with
`Convert.FromHexString` (.NET 5+) or a small loop.
