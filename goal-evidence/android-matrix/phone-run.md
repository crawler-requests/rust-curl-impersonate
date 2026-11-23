OnePlus 9R runbook

The phone is not on this machine. It hangs off another Mac reached over
WireGuard (10.9.0.2), and that link is down at the time of writing: wg0's
last handshake is hours old, ping and ssh both time out, and the machine's
frpc has dropped off the relay (43.228.79.80:7001) as well. Everything that
does not need the phone is done; this file is what to run the moment it is
back.

What the phone is, verified before the link dropped:
  adb serial 9b3d516a, model LE2100 (OnePlus 9R), Android 13 / SDK 33,
  arm64-v8a, WebView 103.0.5060.129,
  fingerprint OnePlus/OnePlus9R_CH/OnePlus9R:13/TP1A.220905.001/...

Reach it:
  cp the key back first (the previous copy under /tmp was removed on
  purpose, and it is a private key):

    sudo -n cp /home/CC11001100/.ssh/id_ed25519 /tmp/.k1
    sudo -n chown $USER /tmp/.k1 && chmod 600 /tmp/.k1

  SSH="ssh -o BatchMode=yes -o IdentitiesOnly=yes -i /tmp/.k1 \
       -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
       CC11001100@10.9.0.2"

  $SSH '/opt/homebrew/bin/adb devices -l'    # 9b3d516a must say `device`

Build the arm64 APKs - or use the ready-made bundle at
/tmp/probe-arm64.tgz (33 APKs: the platform app plus 32 variants, 49 MB).
The Mac has a JDK 17 and an Android SDK at ~/tools/android-sdk; d8/aapt
output does not depend on the host's architecture, so it can be built here
and pushed. To rebuild:

  cd tools/capture/android_phone
  ABI=arm64-v8a ./build.sh                    # app.apk, platform only
  for v in variants/*/; do
      ABI=arm64-v8a ./build.sh --variant "$(basename "$v")"
  done
  # cronet-141.7340.3 needs build-tools 34 (d8 2.1.7 fails on it):
  BUILD_TOOLS=~/Android/Sdk/build-tools/34.0.0 ABI=arm64-v8a \
      ./build.sh --variant cronet-141.7340.3

Run the grid on the phone. device_matrix.py installs each variant in turn
and reads the hello off the wire; it needs only adb on the same machine as
the listener. Push the bundle and run it there (the device's sslip.io name
resolves to its own loopback through adb reverse):

  # /tmp/probe-arm64.tgz is already that bundle; or:
  tar czf probe.tgz -C tools/capture/android_phone \
      --exclude='variants/*/lib' --exclude='variants/*/jni' \
      AndroidManifest.xml build.sh common variant variants app.apk out
  scp -i /tmp/.k1 probe.tgz phone_capture.py firefox_hello.py \
      device_matrix.py CC11001100@10.9.0.2:/tmp/probe/
  $SSH 'cd /tmp/probe && PATH=/opt/homebrew/bin:$PATH \
        python3 -I device_matrix.py --out out-phone --seconds 75 --echo'

  --echo is worth it: it relays the same connection to the real tls.peet.ws
  so the phone's ja4 and Akamai fingerprint are the server's, not our
  parser's, and OkHttp/Cronet/Conscrypt all support the CONNECT proxy.

Then pull the result and rebuild the records:

  scp -i /tmp/.k1 -r CC11001100@10.9.0.2:/tmp/probe/out-phone .
  python3 -I tools/capture/android_matrix_to_raw.py --matrix out-phone
  python3 -I tools/gen_fingerprints.py
  python3 -I tools/audit_provenance.py
  cargo test --workspace

What this run is meant to settle that the containers could not:
  - the phone's own ARM OkHttp 3.x/4.x/5.x, Conscrypt 2.1/2.5 and Cronet
    101/119 hellos, which on an ARM device could differ from x86 in the
    cipher the client picks first;
  - android_okhttp7's Android 7 shape, which no container here can boot;
  - WebView 103 as a live build rather than a replayed capture.

Constraints carried from earlier runs:
  - no LAN address goes in a capture (adb reverse keeps traffic on the
    device's loopback);
  - with --echo the app log holds the device's public egress address, so
    app.log is never committed;
  - the phone is the owner's; the probe only opens a request and aborts the
    handshake, it installs nothing else and changes no settings.
