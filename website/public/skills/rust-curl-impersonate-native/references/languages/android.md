# Android (Kotlin / Java)

Not run on this machine (no Android device/NDK here), but the ABI and packaging
rules are fixed.

## Option A — shared library in `jniLibs`

Fetch the four ABIs you support:

```sh
python3 scripts/fetch_library.py --target aarch64-linux-android        --dest rci-arm64
python3 scripts/fetch_library.py --target armv7-linux-androideabi      --dest rci-armv7
python3 scripts/fetch_library.py --target x86_64-linux-android         --dest rci-x86_64
python3 scripts/fetch_library.py --target i686-linux-android           --dest rci-x86
```

Copy each `lib/librust_curl_impersonate_ffi.so` into
`app/src/main/jniLibs/<abi>/librust_curl_impersonate_ffi.so`
(`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`).

- The Android **shared** build expects the NDK's `libc++_shared.so` at runtime
  (`arguments += "-DANDROID_STL=c++_shared"`, or ship it in `jniLibs`).
- Load it from Kotlin/Java and call through JNA (see `java.md`), or write a
  JNI wrapper.

## Option B — static `.a` + JNI

Link the static library into your NDK module; it does **not** need
`libc++_shared.so` separately (BoringSSL's C++ code is inside the archive). Use
CMake:

```cmake
add_library(rci STATIC IMPORTED)
set_target_properties(rci PROPERTIES IMPORTED_LOCATION
  ${CMAKE_SOURCE_DIR}/libs/${ANDROID_ABI}/librust_curl_impersonate_ffi.a)
target_link_libraries(your-jni-lib rci log)
# The archive is C++; make sure the module itself is C++:
#   extern "C" JNIEXPORT ... (in a .cpp file)
```

Include `rci.h` and call the 17 functions from the `.cpp`; expose a small
`external fun` surface to Kotlin.

## Loading the dynamic form

```kotlin
System.loadLibrary("rust_curl_impersonate_ffi")
```

For JNA, `Native.load("rust_curl_impersonate_ffi", RciLibrary::class.java)`
finds it in `jniLibs` automatically.

## Verify

`verify_abi.py --lib <unpacked>/lib` works only on the host; on a device run a
small instrumented test that does `rci_get(profile, "https://tls.peet.ws/api/all")`
and asserts JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd`.
