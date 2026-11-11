#!/usr/bin/env bash
# Run every locally installed client against tls.peet.ws and keep the echoed
# ClientHello/HTTP2 description. Output goes to tools/capture/raw/.
#
# Set CAPTURE_PYTHON to a Python interpreter with httpx[h2] to capture the
# HTTP/2 httpx record, e.g.
#
#   python3 -m venv --system-site-packages /tmp/fpvenv
#   /tmp/fpvenv/bin/pip install h2
#   CAPTURE_PYTHON=/tmp/fpvenv/bin/python tools/capture/capture.sh
set -u
cd "$(dirname "$0")"
mkdir -p raw
PYTHON="${CAPTURE_PYTHON:-python3}"

run() {
  local name="$1"
  shift
  if "$@" >"raw/$name.log" 2>&1; then
    echo "ok   $name"
  else
    echo "FAIL $name (see raw/$name.log)"
  fi
}

skip() {
  echo "skip $1 ($2)"
}

run go1.26        go run go_client.go raw/go1.26.json
run go1.26_http1  go run go_client.go raw/go1.26_http1.json http1
run curl8.5_h2    curl -sS --http2 https://tls.peet.ws/api/all -o raw/curl8.5_h2.json
run curl8.5_http1 curl -sS --http1.1 https://tls.peet.ws/api/all -o raw/curl8.5_http1.json
run python3.12_requests  "$PYTHON" python_client.py requests  raw/python3.12_requests.json
run python3.12_urllib    "$PYTHON" python_client.py urllib    raw/python3.12_urllib.json
run python3.12_httpclient "$PYTHON" python_client.py httpclient raw/python3.12_httpclient.json
if "$PYTHON" -c "import aiohttp" 2>/dev/null; then
  run python3.12_aiohttp "$PYTHON" python_client.py aiohttp raw/python3.12_aiohttp.json
else
  skip python3.12_aiohttp "aiohttp is missing"
fi
if "$PYTHON" -c "import httpx, h2" 2>/dev/null; then
  run python3.12_httpx "$PYTHON" python_client.py httpx raw/python3.12_httpx.json
else
  skip python3.12_httpx "httpx or h2 is missing; set CAPTURE_PYTHON"
fi
run java21_httpclient java java_capture/Capture.java httpclient raw/java21_httpclient.json
run java21_urlconn    java java_capture/Capture.java urlconnection raw/java21_urlconn.json
run node22_https      node node_capture.js https raw/node22_https.json
run node22_http2      node node_capture.js http2 raw/node22_http2.json
run node22_fetch      node node_capture.js fetch raw/node22_fetch.json
if command -v bun >/dev/null 2>&1; then
  run bun1.3.14 bash -c 'bun -e '"'"'const r = await fetch("https://tls.peet.ws/api/all"); process.stdout.write(await r.text())'"'"' > raw/bun1.3.14.json'
else
  skip bun1.3.14 "bun is missing"
fi
run php8.3_streams php php_capture.php streams raw/php8.3_streams.json
run php8.3_curl    php php_capture.php curl    raw/php8.3_curl.json
run wget1.21.4     wget -qO raw/wget1.21.4.json https://tls.peet.ws/api/all
run perl5_lwp      perl perl_capture.pl raw/perl5_lwp.json
run openssl3_sclient bash -c '(printf "GET /api/all HTTP/1.1\r\nHost: tls.peet.ws\r\nConnection: close\r\n\r\n"; sleep 8) | timeout 30 openssl s_client -quiet -connect tls.peet.ws:443 -servername tls.peet.ws -alpn http/1.1 2>/dev/null | sed -n "/^{/,\$p" > raw/openssl3_sclient.json'
if command -v geckodriver >/dev/null 2>&1; then
  run firefox158 python3 firefox_capture.py raw/firefox158.json
else
  skip firefox158 "geckodriver is missing"
fi
if command -v chromium >/dev/null 2>&1 || command -v chromium-browser >/dev/null 2>&1 \
  || command -v google-chrome >/dev/null 2>&1; then
  run chromium156 python3 chromium_capture.py raw/chromium156.json
else
  skip chromium156 "Chromium is missing"
fi
run rust_reqwest_rustls cargo run --quiet --manifest-path rust_capture/Cargo.toml -- raw/rust_reqwest_rustls.json
# tls-client ships ClientHello definitions for browsers, Android and iOS apps
# that cannot all run on this machine. Build its capture harness once, then
# record each profile.
if command -v go >/dev/null 2>&1; then
  if (cd tlsclient_capture && go build -o ../tlsclient_capture_bin .); then
    for profile in android_confirmed android_confirmed2 android_mesh android_mesh1 \
      android_okhttp7 android_okhttp8 android_okhttp9 android_okhttp10 \
      android_okhttp11 android_okhttp12 android_okhttp13 \
      android_nike android_zalando \
      ios_confirmed ios_safari18_5 ios_safari26 opera91; do
      run "$profile" ./tlsclient_capture_bin "raw/$profile.json" "$profile"
    done
    for profile in brave146 cloudflare \
      chrome103 chrome104 chrome105 chrome106 chrome107 chrome108 chrome109 \
      chrome110 chrome111 chrome112 chrome117 chrome120 chrome124 chrome131 \
      chrome133 chrome144 chrome146 chrome150 chrome152 \
      firefox102 firefox104 firefox105 firefox106 firefox108 firefox110 \
      firefox117 firefox120 firefox123 firefox132 firefox133 firefox135 \
      firefox147 firefox148 \
      opera89 opera90 safari15_6_1 safari16 safari_ipad15_6 \
      ios_mms ios_mms2 ios_mms3 ios_mesh ios_mesh2 ios_nike ios_zalando \
      ios_safari15_5 ios_safari15_6 ios_safari16 ios_safari17 ios_safari18; do
      run "tlsclient_$profile" ./tlsclient_capture_bin "raw/tlsclient_$profile.json" "$profile"
    done
    rm -f tlsclient_capture_bin
  else
    skip tls-client "go build failed"
  fi
else
  skip tls-client "go is missing"
fi
# uTLS only shapes the TLS handshake, so it is captured over HTTP/1.1 and the
# records carry only the ClientHello. It covers older Chrome/Firefox and the
# Chinese browsers tls-client does not define.
if command -v go >/dev/null 2>&1; then
  if (cd utls_capture && go build -o ../utls_capture_bin .); then
    for profile in chrome58 chrome62 chrome70 chrome72 chrome83 chrome87 \
      chrome96 chrome100 chrome102 chrome106shuffle chrome115pq chrome120 \
      chrome120pq chrome131 chrome133 \
      firefox55 firefox56 firefox63 firefox65 firefox99 firefox102 \
      firefox105 firefox120 \
      safari16 ios11 ios12 ios13 ios14 android11okhttp edge85 edge106 \
      360_7_5 360_11_0 qq11_1; do
      run "utls_$profile" ./utls_capture_bin "raw/utls_$profile.json" "$profile"
    done
    rm -f utls_capture_bin
  else
    skip utls "go build failed"
  fi
else
  skip utls "go is missing"
fi

echo
echo "raw captures:"
ls -l raw/*.json | awk '{print $5, $9}'
