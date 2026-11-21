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
