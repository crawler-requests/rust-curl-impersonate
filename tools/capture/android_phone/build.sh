#!/bin/bash
# Build the probe APK for a real phone.
#
# Needs a JDK, an Android SDK (android.jar + build-tools) and the OkHttp 4.12
# jar with its kotlin/okio dependencies. Paths can be overridden:
#
#   ANDROID_JAR=... OKHTTP_JAR=... KOTLIN_JAR=... OKIO_JAR=... ./build.sh
#
# Output: app.apk next to this script.

set -euo pipefail
cd "$(dirname "$0")"

SDK="${ANDROID_SDK:-$HOME/Android/Sdk}"
ANDROID_JAR="${ANDROID_JAR:-$SDK/platforms/android-33/android.jar}"
BUILD_TOOLS="${BUILD_TOOLS:-$SDK/build-tools/30.0.3}"
OKHTTP_JAR="${OKHTTP_JAR:-$HOME/.m2/repository/com/squareup/okhttp3/okhttp/4.12.0/okhttp-4.12.0.jar}"
KOTLIN_JAR="${KOTLIN_JAR:-$HOME/.m2/repository/org/jetbrains/kotlin/kotlin-stdlib/1.9.25/kotlin-stdlib-1.9.25.jar}"
OKIO_JAR="${OKIO_JAR:-$HOME/.m2/repository/com/squareup/okio/okio-jvm/3.6.0/okio-jvm-3.6.0.jar}"
KEYSTORE="${KEYSTORE:-$HOME/.android/debug.keystore}"

rm -rf classes dex
mkdir -p classes dex

javac -source 8 -target 8 -bootclasspath "$ANDROID_JAR" \
    -cp "$OKHTTP_JAR:$KOTLIN_JAR:$OKIO_JAR" \
    -d classes Main.java RunStacks.java WebViewLoader.java RequestThread.java \
    2>&1 | grep -v "bootstrap class path" || true

"$BUILD_TOOLS/d8" --release --min-api 30 --lib "$ANDROID_JAR" \
    --output dex \
    $(find classes -name '*.class') \
    "$OKHTTP_JAR" "$KOTLIN_JAR" "$OKIO_JAR"

rm -f app-unsigned.apk app.apk
"$BUILD_TOOLS/aapt" package -f -M AndroidManifest.xml -I "$ANDROID_JAR" \
    -F app-unsigned.apk
(cd dex && "$BUILD_TOOLS/aapt" add ../app-unsigned.apk classes.dex >/dev/null)
"$BUILD_TOOLS/zipalign" -f 4 app-unsigned.apk app.apk
"$BUILD_TOOLS/apksigner" sign --ks "$KEYSTORE" --ks-pass pass:android \
    --key-pass pass:android app.apk

echo "built $(pwd)/app.apk"
