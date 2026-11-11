#!/usr/bin/env bash
# Capture real fingerprints of runtime versions that are not installed on this
# machine, using the upstream Docker images. Each image ships the runtime with
# its bundled TLS library (Go's crypto/tls, Node's OpenSSL, PHP's OpenSSL,
# GnuTLS for Debian wget), so the recorded ClientHello is the one production
# servers see from that version. Output goes to tools/capture/raw/.
#
# Recipes that only need to run a program write the file through the mounted
# /out directory; recipes that install a package (apk/apt need root) stream the
# JSON to stdout instead, because files written by root would be unreadable in
# the next step for the build user.
set -u
cd "$(dirname "$0")"
mkdir -p raw
ROOT="$(pwd)"
UID_GID="$(id -u):$(id -g)"

run() {
  local name="$1"
  shift
  if docker run --rm -u "$UID_GID" -v "$ROOT":/cap:ro -v "$ROOT/raw":/out "$@" \
    >"raw/$name.log" 2>&1; then
    echo "ok   $name"
  else
    echo "FAIL $name (see raw/$name.log)"
  fi
}

# Run as root so apk/apt can install the client, then take the JSON from
# stdout.
runout() {
  local name="$1"
  shift
  if docker run --rm -v "$ROOT":/cap:ro "$@" >"raw/$name.json" 2>"raw/$name.log"; then
    echo "ok   $name"
  else
    echo "FAIL $name (see raw/$name.log)"
  fi
}

# Go: crypto/tls changes the ClientHello every release. 1.26 is captured from
# the local toolchain by capture.sh; these cover the older ones.
for v in 1.19 1.20 1.21 1.22 1.23 1.24 1.25; do
  run "go$v" golang:$v-alpine sh -c \
    "cd /tmp && GOCACHE=/tmp/gocache go run /cap/go_client.go /out/go$v.json"
done

# Node bundles its own OpenSSL; 24 (OpenSSL 3.5) differs from 18/20/22.
for v in 18 20 24; do
  run "node${v}_https" node:$v-alpine node /cap/node_capture.js https /out/node${v}_https.json
  run "node${v}_http2" node:$v-alpine node /cap/node_capture.js http2 /out/node${v}_http2.json
done

# curl links the image's OpenSSL: 7.88.1 is OpenSSL 1.1.1, 8.10.1 is 3.x.
for v in 7.88.1 8.10.1; do
  run "curl${v}_h2" curlimages/curl:$v sh -c \
    "curl -sS --http2 https://tls.peet.ws/api/all -o /out/curl${v}_h2.json"
  run "curl${v}_http1" curlimages/curl:$v sh -c \
    "curl -sS --http1.1 https://tls.peet.ws/api/all -o /out/curl${v}_http1.json"
done

# Python's ssl module follows the image's OpenSSL 3.5; 3.10-3.13 share one
# ClientHello, 3.9 has its own, and 3.8 keeps OpenSSL 1.1.1.
for v in 3.8 3.9 3.10 3.11 3.13; do
  run "python${v}_urllib" python:${v}-slim \
    python3 /cap/python_client.py urllib /out/python${v}_urllib.json
done

# Java 8 has no java.net.http client; 11, 17 and 21 have both stacks.
runout java8_urlconn eclipse-temurin:8-jdk sh -c \
  "cd /tmp && javac -d /tmp /cap/java_capture/Capture8.java && java -cp /tmp Capture8 urlconn /dev/stdout"
for v in 11 17; do
  runout "java${v}_httpclient" eclipse-temurin:${v}-jdk sh -c \
    "cd /tmp && javac -d /tmp /cap/java_capture/Capture.java && java -cp /tmp Capture httpclient /dev/stdout"
  runout "java${v}_urlconn" eclipse-temurin:${v}-jdk sh -c \
    "cd /tmp && javac -d /tmp /cap/java_capture/Capture.java && java -cp /tmp Capture urlconn /dev/stdout"
done

# OpenSSL s_client from distro packages: 1.1.1w (Alpine 3.15), 3.1, 3.3.
sclient='(printf "GET /api/all HTTP/1.1\r\nHost: tls.peet.ws\r\nConnection: close\r\n\r\n"; sleep 8) | timeout 30 openssl s_client -quiet -connect tls.peet.ws:443 -servername tls.peet.ws -alpn http/1.1 2>/dev/null | sed -n "/^{/,\$p"'
runout openssl1.1_sclient alpine:3.15 sh -c "apk add -q openssl 2>/dev/null; $sclient"
runout openssl3.1_sclient alpine:3.18 sh -c "apk add -q openssl 2>/dev/null; $sclient"
runout openssl3.3_sclient alpine:3.20 sh -c "apk add -q openssl 2>/dev/null; $sclient"

# PHP streams: 7.4 links OpenSSL 1.1.1, 8.1 and 8.2 link OpenSSL 3.5.
for v in 7.4 8.1 8.2; do
  run "php${v}_streams" php:$v-cli php /cap/php_capture.php streams /out/php${v}_streams.json
done

# Debian's wget uses GnuTLS with a much smaller cipher list than the local one.
runout wget1.21_bookworm debian:bookworm-slim sh -c \
  'apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq wget >/dev/null 2>&1; wget -qO- https://tls.peet.ws/api/all'

# Ruby's Net::HTTP links the image's OpenSSL.
run ruby3.3_nethttp ruby:3.3-alpine ruby /cap/ruby_capture.rb /out/ruby3.3_nethttp.json

# Deno's fetch goes through rustls, so its ClientHello is not OpenSSL's.
run deno_fetch denoland/deno:alpine sh -c \
  "deno eval --allow-net --allow-write 'const r = await fetch(\"https://tls.peet.ws/api/all\"); Deno.writeTextFileSync(\"/out/deno_fetch.json\", await r.text())'"

# Dart's dart:io HTTPS is its own BoringSSL build.
run dart_httpclient dart:stable sh -c "dart /cap/dart_capture.dart /out/dart_httpclient.json"

# Erlang/OTP's ssl module over inets' httpc (HTTP/1.1 only).
run erlang_ssl erlang:27 sh -c "escript /cap/erlang_capture.escript /out/erlang_ssl.json"

# .NET's SocketsHttpHandler over the runtime's OpenSSL. The SDK CLI wants a
# writable HOME and runs as root for its first-use setup, so the recipe runs
# unprivileged as nothing and writes root-owned JSON into /out; chown it
# afterwards. http1 is the default HttpClient version, http2 is explicit.
if docker run --rm -e DOTNET_CLI_TELEMETRY_OPTOUT=1 -e DOTNET_NOLOGO=1 \
  -v "$ROOT":/cap:ro -v "$ROOT/raw":/out mcr.microsoft.com/dotnet/sdk:8.0 sh -c \
  "export HOME=/root DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1; cd /tmp && dotnet new console --force -o app >/dev/null 2>&1; cd app && cp /cap/dotnet_capture.cs Program.cs && dotnet run --project . /out/dotnet8_http1.json http1 >/dev/null && dotnet run --project . /out/dotnet8_http2.json http2 >/dev/null" \
  >raw/dotnet8.log 2>&1; then
  echo "ok   dotnet8_http1 dotnet8_http2"
else
  echo "FAIL dotnet8 (see raw/dotnet8.log)"
fi

# The dotnet recipe ran as root inside the container.
sudo -n chown "$(id -u):$(id -g)" raw/dotnet8_*.json 2>/dev/null

echo
ls -l raw/go1.*.json raw/node1*.json raw/node2*.json raw/curl7*.json \
  raw/curl8.10*.json raw/python3.*_urllib.json raw/java*.json raw/openssl*.json \
  raw/php*.json raw/wget*.json raw/ruby*.json raw/deno*.json raw/dart*.json \
  raw/erlang*.json raw/dotnet*.json 2>/dev/null | awk '{print $5, $9}'
