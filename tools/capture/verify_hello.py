#!/usr/bin/env python3
"""Check a record's ClientHello against what the real client sends a real server.

The library's captures mostly come from a local socket or the echo service.
This verifies the wire bytes the client actually put on a connection to a
public server, using the kernel's packet dumper - code we did not write - so a
bug in a capture harness cannot survive it.

Usage:
    sudo python3 -I tools/capture/verify_hello.py firefox --binary /path/to/firefox \
        --url https://tls.peet.ws/api/all [--record firefox157]

Prints the extension list and cipher list from the pcap, and whether they match
the named record. Exits non-zero on a mismatch.
"""

import argparse
import json
import os
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import firefox_hello as hello  # noqa: E402


def resolve_host(url):
    from urllib.parse import urlparse
    import socket
    host = urlparse(url).hostname
    return host, socket.gethostbyname(host)


def capture_pcap(host_ip, seconds, run):
    """Run `run()` while tcpdump watches traffic to host_ip:443. Returns bytes."""
    path = tempfile.mktemp(suffix=".pcap")
    dump = subprocess.Popen(
        ["tcpdump", "-i", "any", "-w", path, "-s", "0",
         "tcp port 443 and host " + host_ip],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(3)
    try:
        run(seconds)
    finally:
        time.sleep(2)
        dump.terminate()
        dump.wait(timeout=10)
    with open(path, "rb") as handle:
        data = handle.read()
    os.unlink(path)
    return data


def client_hellos(pcap):
    """Every ClientHello in the capture, deduplicated by TCP sequence.

    `tcpdump -i any` records each packet once per direction of the pseudo
    device, so the same segment arrives twice.
    """
    offset = 24
    streams = {}
    seen = set()
    while offset + 16 <= len(pcap):
        _, _, incl, _ = struct.unpack("<IIII", pcap[offset:offset + 16])
        offset += 16
        packet = pcap[offset:offset + incl]
        offset += incl
        if len(packet) < 20 or struct.unpack(">H", packet[0:2])[0] != 0x0800:
            continue
        ip = packet[20:]
        if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 6:
            continue
        total = int.from_bytes(ip[2:4], "big")
        ihl = (ip[0] & 0xF) * 4
        if total > len(ip) or len(ip) < ihl + 20:
            continue
        tcp = ip[ihl:total]
        src = int.from_bytes(tcp[0:2], "big")
        dst = int.from_bytes(tcp[2:4], "big")
        seq = int.from_bytes(tcp[4:8], "big")
        payload = tcp[(tcp[12] >> 4) * 4:]
        if not payload:
            continue
        key = (src, dst, seq)
        if key in seen:
            continue
        seen.add(key)
        if 443 in (src, dst):
            streams.setdefault((src, dst), []).append((seq, payload))
    found = []
    for segments in streams.values():
        segments.sort()
        stream = b"".join(payload for _, payload in segments)
        if stream and stream[0] == 0x16 and len(stream) > 5 and stream[5] == 1:
            length = int.from_bytes(stream[3:5], "big")
            found.append(stream[:5 + length])
    return found


def describe(data):
    ciphers, extensions = hello.parse(data)
    return {
        "ciphers": [hello.CIPHER_NAMES.get(c, f"0x{c:04x}") for c in ciphers],
        "extensions": [hello.describe(k, p)["name"].split(" (")[0] for k, p in extensions],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("generator", help="the client, e.g. firefox")
    parser.add_argument("--binary")
    parser.add_argument("--url", default="https://tls.peet.ws/api/all")
    parser.add_argument("--record")
    parser.add_argument("--seconds", type=int, default=60)
    args = parser.parse_args()

    host, host_ip = resolve_host(args.url)
    print(f"host {host} -> {host_ip}", flush=True)

    def run(seconds):
        profile = tempfile.mkdtemp(prefix=f"{args.generator}-verify-")
        subprocess.run(
            [args.binary, "-headless", "-no-remote", "-profile", profile,
             "--screenshot", os.path.join(profile, "shot.png"), args.url],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=seconds,
        )

    pcap = capture_pcap(host_ip, args.seconds, run)
    hellos = client_hellos(pcap)
    if not hellos:
        raise SystemExit("no ClientHello in the capture")

    observed = describe(hellos[0])
    print(f"captured {len(hellos)} hello(s); using the first")
    print("  ciphers   :", len(observed["ciphers"]))
    print("  extensions:", observed["extensions"])

    if not args.record:
        return 0

    library = json.load(open(os.path.join(
        HERE, "..", "..", "src", "fingerprint", "builtin.json")))
    record = next(
        (r for r in library["fingerprints"] if r["name"] == args.record), None)
    if record is None:
        raise SystemExit(f"no record named {args.record}")

    expected_ciphers = [c for c in record["tls"]["ciphers"].split(":") if c]
    expected_extensions = [e["name"].split(" (")[0]
                           for e in json.load(open(
                               os.path.join(HERE, "raw", args.record + ".json"))
                           )["tls"]["extensions"]]

    # The library writes `delegated_credentials`; tls.peet.ws and this parser
    # say `delegated_credential`. Same extension (34), so normalise the label
    # rather than reporting a mismatch that is not on the wire.
    def same_name(name):
        return name.rstrip("s")

    ciphers_ok = [c for c in expected_ciphers if "GREASE" not in c] == \
                 [c for c in observed["ciphers"] if "GREASE" not in c]
    extensions_ok = ([same_name(n) for n in expected_extensions] ==
                     [same_name(n) for n in observed["extensions"]])

    print(f"  ciphers match   : {ciphers_ok}")
    print(f"  extensions match: {extensions_ok}")
    if not (ciphers_ok and extensions_ok):
        print("  record :", expected_extensions)
        print("  live   :", observed["extensions"])
        return 1
    print(f"OK: {args.record} matches the wire bytes {args.generator} sent {host}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
