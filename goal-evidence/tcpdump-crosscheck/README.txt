Device-side tcpdump cross-check, 2026-11-21

Why: the earlier Cronet and SwiftNIO records were captured with a listener
this repo wrote. A listener records what the kernel hands it, but it is still
code we control, so a bug in it would look like a valid capture. These files
come from the kernel's own packet dumper instead.

cronet: /system/bin/tcpdump -i any -w cap.pcap on the redroid device, while
the Cronet 100 APK made a real request to tls.peet.ws (205.185.123.167:443).
  realhello.bin   517 bytes, 16 ciphers, 18 extensions
  Result: identical, item for item, to tools/capture/raw/cronet_android100.json
  (same cipher order, same 18 extensions in the same order, same GREASE
  positions). The cross-check passed.

swiftnio: niocap (swift-nio-ssl 2.36) sending one hello to a socket.
  nio_hello_direct.bin   517 bytes, 17 ciphers, 12 extensions
  Result: TLS block identical to tools/capture/raw/swiftnio_ssl.json.

What the cross-check caught: the swiftnio record listed four request headers
(user-agent CFNetwork/1474, accept, accept-encoding, accept-language) that no
capture ever contained. They were hardcoded in the harness. The harness is a
bare NIOHTTP2 client and sends no headers, so the record now carries none.
That was a real defect and it is exactly the class of mistake a self-written
capture path invites.

Two traps found while doing this, kept here so they are not repeated:
  - `tcpdump -i any` captures each packet twice (once per direction of the
    pseudo-device). Deduplicate by 4-tuple and sequence number.
  - the first attempt caught connectivitycheck.gstatic.com, an Android system
    probe, not the app traffic. Verify the SNI in every capture before using
    it; a 517-byte hello that looks right can still be the wrong connection.
