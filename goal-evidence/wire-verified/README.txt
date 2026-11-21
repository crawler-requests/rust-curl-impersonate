End-to-end verification: real client -> real server -> kernel dumper, 2026-11-22

The library's captures mostly come from a local socket or the echo service.
This is the stronger check: run the real client, let it connect to a real
server, and read the ClientHello out of the kernel's own packet capture with
tcpdump. Nothing in that path is code this repo wrote, so a bug in a capture
harness cannot survive it.

tools/capture/verify_hello.py automates it:
    sudo python3 -I tools/capture/verify_hello.py firefox \
        --binary <firefox> --record <record>

verified 2026-11-22, all against https://tls.peet.ws/api/all

  record        client              ciphers  extensions
  firefox142    Firefox 142.0        match      match
  firefox146    Firefox 146.0        match      match
  firefox151    Firefox 151.0        match      match
  firefox157    Firefox 157.0        match      match
  firefox158    Firefox 158.0        match      match

That settles the question the 31 firefox121-157 records raised. They were
captured from Firefox's own TLS stack pointed at a local socket, so their JA4
records only the a-segment (`..._-`). The five versions above prove the bytes
on that socket are the bytes Firefox sends to a server - the extension lists
and cipher lists are identical. Mozilla has retired the 121-141 tarballs from
its CDN, so those exact builds cannot be re-downloaded; the method they used
is the same one verified here.

Also in this pass:
  audit_provenance.py   checks every record: raw file exists, has a real
                        ClientHello, and claims no header or HTTP/2 parameter
                        that the capture does not contain. 231/231 clean.
                        This is the check that would have caught the swiftnio
                        record's invented headers.

  Chromium 141 (Playwright build, local) was captured through tcpdump too:
  16 ciphers, 19-20 extensions including trust_anchors 51764, ALPS, ECH
  GREASE. It is not in the library (that build was never recorded), but it
  confirms the Chromium capture path produces real wire bytes.

--- round 2: re-captured from the exact builds (2026-11-22) ---

Every Chrome record whose build could still be downloaded was re-captured
with that exact version and compared:

  record          build            state       result
  chromium157     157.0.8103.78   first       ja4 t13d1518h2_... identical
  chrome158       158.0.8127.18   resumed     ja4 t13d1519h2_... identical
  chrome159       159.8144.0      resumed     ja4 t13d1519h2_... identical
  chrome160       160.0.8167.0    first       ja4 t13d1518h2_... identical

All four came back byte-identical on cipher list, extension list and JA4.

Two things this round settled:

  1. A Chromium ClientHello has two states - a first connection and a resumed
     one with `pre_shared_key` - and they differ by one extension and by the
     JA4 a-segment that counts it. chrome158/159 were captured resumed,
     chromium157/chrome160 first-connection. tools/capture/verify_chromium.py
     drives one browser process over CDP (so it can reach the resumed state)
     and reports which state it saw.

  2. The local Snap Chromium is 157.0.8103.38, and it does NOT send extension
     4832, while the Chrome for Testing Stable build 157.0.8103.78 does. The
     library's chromium157 is the CfT build, which is why a Snap re-run looks
     like a mismatch. This was already recorded when the record was moved to
     the CfT build; the re-capture confirms it.

Negative test: pointing the Snap build at chrome160's record correctly fails
(27 extensions vs 18, different JA4), so the verifier is not a rubber stamp.

--- round 3: Android OkHttp on a real device (2026-11-22) ---

The android_okhttp* records came from tls-client's OkHttp profiles. That is a
profile definition, not a device, so the stronger check is to run OkHttp
itself. Built a small APK against okhttp 4.12.0 and ran it on the redroid
Android 13 device with /system/bin/tcpdump watching:

  live OkHttp 4.12, Android 13, to tls.peet.ws
    15 ciphers, 13 extensions, ja4 a-segment t13d1513h2
    server_name, extended_master_secret, renegotiation_info, supported_groups,
    ec_point_formats, session_ticket, ALPN, status_request, sig_algs,
    key_share, psk_key_exchange_modes, supported_versions, padding

  android_okhttp12 / android_okhttp13 records
    ja4 t13d1513h2_8daaf6152771_eca864cca44a, 13 extensions, same set

Identical. The packet capture is kept as okhttp_android13.pcap.
