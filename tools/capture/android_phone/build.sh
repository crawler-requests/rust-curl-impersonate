#!/bin/bash
# Build the probe APK for a device.
#
#   ./build.sh                      platform-only build -> app.apk
#   ./build.sh --variant DIR        link the version in variants/DIR
#                                   -> out/DIR.apk
#
# d8 cannot link two copies of the same package, so each variant is its own
# APK. That is deliberate: a hello captured under the `okhttp-4-12-0` label
# came from OkHttp 4.12.0, with nothing in the path that could substitute
# another client.
#
# A variant directory holds Variant.java, an optional lib/ with every jar to
# link, and an optional jni/<abi>/*.so for native code. Needs a JDK and an
# Android SDK; paths can be overridden:
#
#   ANDROID_SDK=... ANDROID_JAR=... BUILD_TOOLS=... KEYSTORE=... ./build.sh

set -euo pipefail
cd "$(dirname "$0")"

SDK="${ANDROID_SDK:-$HOME/Android/Sdk}"
ANDROID_JAR="${ANDROID_JAR:-$SDK/platforms/android-33/android.jar}"
BUILD_TOOLS="${BUILD_TOOLS:-$SDK/build-tools/30.0.3}"
KEYSTORE="${KEYSTORE:-$HOME/.android/debug.keystore}"
MIN_API="${MIN_API:-21}"
ABI="${ABI:-}"

VARIANT=""
if [ "${1:-}" = "--variant" ]; then
    VARIANT="${2:?--variant needs a directory name}"
fi

if [ -n "$VARIANT" ]; then
    SRC="variants/$VARIANT"
    OUT="out/$VARIANT.apk"
else
    SRC=""
    OUT="app.apk"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/classes" "$WORK/dex" "$WORK/apk/lib" "$(dirname "$OUT")"

cp common/*.java "$WORK/"
cp "${SRC:-variant}/Variant.java" "$WORK/Main.java.tmp" 2>/dev/null || true
# Only the variant's own Variant.java is compiled; the template stays out.
if [ -n "$SRC" ]; then
    cp "$SRC/Variant.java" "$WORK/"
else
    cp variant/Variant.java "$WORK/"
fi
rm -f "$WORK/Main.java.tmp"

JARS=()
if [ -n "$SRC" ] && [ -d "$SRC/lib" ]; then
    while IFS= read -r -d '' jar; do JARS+=("$jar"); done \
        < <(find "$SRC/lib" -name '*.jar' -print0 | sort -z)
fi

CP="$(IFS=:; echo "${JARS[*]:-}")"
javac -nowarn -source 8 -target 8 -bootclasspath "$ANDROID_JAR" \
    ${CP:+-cp "$CP"} -d "$WORK/classes" "$WORK"/*.java

# --debug keeps every class name: Cronet finds its own providers by
# reflection on hard-coded class names, and shrinking renames them.
"$BUILD_TOOLS/d8" --debug --min-api "$MIN_API" --lib "$ANDROID_JAR" \
    --output "$WORK/dex" \
    $(find "$WORK/classes" -name '*.class') \
    ${JARS[@]+"${JARS[@]}"}

rm -f "$WORK/unsigned.apk"
"$BUILD_TOOLS/aapt" package -f -M AndroidManifest.xml -I "$ANDROID_JAR" \
    -F "$WORK/unsigned.apk"
(cd "$WORK/dex" && "$BUILD_TOOLS/aapt" add "../unsigned.apk" classes.dex >/dev/null)

# Native code, when the variant ships any (Conscrypt, Cronet): aapt stores
# each file at the path it is given, so copy them under lib/<abi>/ first.
if [ -n "$SRC" ] && [ -d "$SRC/jni" ]; then
    for abi in "$SRC"/jni/*/; do
        abi_name="$(basename "$abi")"
        # ABI=<name> keeps only that ABI's native libraries; unset means all.
        if [ -n "$ABI" ] && [ "$abi_name" != "$ABI" ]; then
            continue
        fi
        mkdir -p "$WORK/apk/lib/$abi_name"
        cp "$abi"* "$WORK/apk/lib/$abi_name/" 2>/dev/null || true
    done
    (cd "$WORK/apk" && for so in lib/*/*.so; do
        [ -e "$so" ] || continue
        "$BUILD_TOOLS/aapt" add "$WORK/unsigned.apk" "$so" >/dev/null
    done)
fi

"$BUILD_TOOLS/zipalign" -f 4 "$WORK/unsigned.apk" "$WORK/aligned.apk"
"$BUILD_TOOLS/apksigner" sign --ks "$KEYSTORE" --ks-pass pass:android \
    --key-pass pass:android --out "$OUT" "$WORK/aligned.apk"

echo "built $(pwd)/$OUT"
