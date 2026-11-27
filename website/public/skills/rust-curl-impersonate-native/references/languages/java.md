# Java / Kotlin (JVM) — JNA

Verified working: 15 JUnit tests pass and the HTTP/3 case is skipped unless you opt in (`-Drci.h3=1`). The
archive ships a standalone Maven project under `java/`; a copy is in this
skill's `assets/java/`.

## Use the shipped project

```sh
cd java
mvn -o package -DskipTests   # tests need a local server, see below
```

It produces a jar. Depend on JNA (`net.java.dev.jna:jna:5.17.0`) plus that jar.

```java
try (RustCurlImpersonate.Client client = RustCurlImpersonate.client("chrome150")) {
    RustCurlImpersonate.Response reply = client.get("https://tls.peet.ws/api/all");
    System.out.println(reply.status() + " " + reply.version());
    System.out.println(reply.bodyText().substring(0, 200));
}
```

## If you write your own declarations

```java
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

public interface RciLibrary extends Library {
    RciLibrary INSTANCE = Native.load("rust_curl_impersonate_ffi", RciLibrary.class);

    int rci_version();
    Pointer rci_targets();                 // Pointer, not String
    Pointer rci_get(String profile, String url);
    String rci_last_error();               // borrowed: String is safe here
    void rci_string_free(Pointer text);
}
```

Rules:

- `char *` **results** must be `Pointer`, read with `getString(0, "UTF-8")`,
  then `rci_string_free`. Declaring them `String` lets JNA copy and drop the
  original pointer — freeing it then crashes.
- `const char *` **inputs** can be `String`; JNA converts to UTF-8.
- `size_t` (the `body_len` of `rci_request`) is `long`.
- `RciClient *` is `Pointer` (an opaque handle).

Generate the whole interface body from the header:

```sh
python3 scripts/gen_declarations.py --header rci/include/rci.h --java
```

## Why JNA and not Panama

Panama (FFM API) is still preview on JDK 21 and needs `--enable-preview` /
`--enable-native-access`; JNA works on JDK 8–25 with no such flags. If the
project already standardizes on Panama, the same ownership rules apply: treat
`char *` results as addresses and free them with `rci_string_free`.

## Library path

`RciNative` looks for, in order: system property `rci.lib`, env `RCI_LIB`, a
classpath resource `/rci/<platform>/<library name>` (for a jar that bundles
the native library), then JNA's normal search path (`jna.library.path`).

## Test

```sh
python3 scripts/local_echo_server.py 8765 &
cd java && RCI_LIB=/path/to/lib/librust_curl_impersonate_ffi.so \
  RCI_BASE=http://127.0.0.1:8765 mvn -o test
```

Add `-Drci.h3=1` for a live HTTP/3 case (needs outbound UDP; it retries).
