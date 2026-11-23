#!/usr/bin/env python3
"""Capture a real Android phone's ClientHello for each of its TLS stacks.

The phone is driven by a small probe app (tools/capture/android_phone). It
makes one request per stack to a hostname that sslip.io resolves back to this
machine:

    conscrypt.<our-ip>.sslip.io   HttpsURLConnection, the platform stack
    okhttp.<our-ip>.sslip.io      the app-bundled OkHttp 4.12
    webview.<our-ip>.sslip.io     the system WebView

The SNI therefore names the stack, so no root is needed to edit /etc/hosts
and each capture is unambiguous. This script listens, never answers the
handshake, and writes the bytes it saw.

It can also relay a CONNECT tunnel so the app reaches the real
tls.peet.ws through this machine; the report that comes back is computed by
the service, not by our parser, which is the strongest evidence available.
Give it with --echo.

`--reverse` keeps the phone's traffic on its own loopback: adb forwards
tcp:8443 back to this machine, and 127-0-0-1.sslip.io still resolves to
127.0.0.1, so no LAN address appears in the capture. Without it the phone
connects to this machine's LAN address directly.

This script runs on the machine the phone is attached to (it needs adb):

    python3 tools/capture/phone_capture.py --serial <serial> --out DIR \
        [--apk tools/capture/android_phone/app.apk] [--reverse] [--echo] \
        [--record NAME]

`--record` compares the captures with one library record and exits non-zero
on a mismatch.
"""

import argparse
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import firefox_hello as hello  # noqa: E402

PACKAGE = "io.capture.phone"
ACTIVITY = PACKAGE + "/.Main"


def is_grease(value):
    return (value & 0x0F0F) == 0x0A0A


def sigalgs_of(extensions):
    """Signature algorithm codes from extension 13, in wire order."""
    for kind, payload in extensions:
        if kind == 13 and len(payload) >= 2:
            size = struct.unpack(">H", payload[:2])[0]
            return [struct.unpack(">H", payload[2 + i:4 + i])[0]
                    for i in range(0, min(size, len(payload) - 2), 2)]
    return []


def full_ja4(ciphers, extensions):
    """JA4 with the b/c hashes computed the way tls.peet.ws does."""
    import hashlib

    head = hello.ja4(ciphers, extensions).split("_")[0]
    cipher_list = sorted(f"{c:04x}" for c in ciphers if not is_grease(c))
    ext_list = sorted(
        f"{kind:04x}" for kind, _ in extensions
        if not is_grease(kind) and kind not in (0, 16)
    )
    # c = sha256("<sorted extensions>_<signature algorithms in wire order>");
    # the sigalgs are what separates clients with the same extension set.
    text = ",".join(ext_list)
    sigalgs = sigalgs_of(extensions)
    if sigalgs:
        text += "_" + ",".join(f"{code:04x}" for code in sigalgs)

    def digest(values):
        return hashlib.sha256(values.encode()).hexdigest()[:12]

    return "%s_%s_%s" % (head, digest(",".join(cipher_list)), digest(text))


def sni_of(extensions):
    for kind, payload in extensions:
        if kind == 0 and len(payload) >= 5:
            size = struct.unpack(">H", payload[3:5])[0]
            return payload[5:5 + size].decode("ascii", "replace")
    return ""


def read_hello(sock, prefix=b"", timeout=12.0):
    """Read one TLS handshake into memory, however it is segmented."""
    sock.settimeout(timeout)
    buf = prefix
    deadline = time.time() + timeout
    while time.time() < deadline:
        if len(buf) >= 9:
            if buf[0] != 0x16 or buf[5] != 1:
                return None, buf
            body = int.from_bytes(buf[6:9], "big")
            if len(buf) >= 9 + body:
                return buf[:9 + body], buf[9 + body:]
        try:
            chunk = sock.recv(16384)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    return None, buf


class Recorder:
    def __init__(self, outdir):
        self.outdir = outdir
        self.lock = threading.Lock()
        self.entries = []
        # Filled in from the device itself before listening starts.
        self.device = ""
        self.fingerprint = ""
        self.label = ""
        self.stacks = ""
        os.makedirs(outdir, exist_ok=True)

    def add(self, record, meta):
        ciphers, extensions = hello.parse(record)
        name = sni_of(extensions) or meta.get("label") or "tls"
        name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_")
        with self.lock:
            index = len(self.entries)
            stem = "%02d_%s" % (index, name)
            raw_path = os.path.join(self.outdir, stem + ".bin")
            json_path = os.path.join(self.outdir, stem + ".json")
            with open(raw_path, "wb") as handle:
                handle.write(record)
            document = {
                "tls": {
                    "ja4": full_ja4(ciphers, extensions),
                    "ciphers": [
                        "TLS_GREASE (0x%04X)" % c if is_grease(c)
                        else hello.CIPHER_NAMES.get(c, "TLS_UNKNOWN_%#06x" % c)
                        for c in ciphers
                    ],
                    "extensions": [hello.describe(k, p) for k, p in extensions],
                },
                "http_version": "",
                "method": "",
                "user_agent": "",
                "sni": sni_of(extensions),
                "captured": "ClientHello only (a local listener recorded it)",
                "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "device": self.device,
                "build_fingerprint": self.fingerprint,
                "build_label": self.label,
                "stacks": self.stacks,
                "harness": "tools/capture/phone_capture.py + tools/capture/android_phone",
                "peer": meta.get("peer", ""),
                "via": meta.get("via", ""),
            }
            with open(json_path, "w", encoding="utf-8") as handle:
                json.dump(document, handle, indent=1)
            self.entries.append(document)
        names = [e["name"].split(" (")[0] for e in document["tls"]["extensions"]]
        print("  captured %-34s ja4=%s" % (name, document["tls"]["ja4"]))
        print("    " + ", ".join(names))
        return document


class DirectListener(threading.Thread):
    """Reads the ClientHello of a connection that starts with TLS."""

    def __init__(self, port, recorder):
        threading.Thread.__init__(self)
        self.daemon = True
        self.port = port
        self.recorder = recorder
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # A previous run's socket can still be closing when the next cell
        # starts; retry briefly instead of failing the whole capture.
        for attempt in range(20):
            try:
                self.sock.bind(("0.0.0.0", port))
                break
            except OSError:
                if attempt == 19:
                    raise
                time.sleep(0.5)
        self.sock.listen(32)
        self.sock.settimeout(1.0)
        self.stopping = False

    def run(self):
        while not self.stopping:
            try:
                conn, peer = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                record, _ = read_hello(conn)
                if record:
                    self.recorder.add(record, {
                        "peer": "%s:%d" % peer, "via": "direct",
                    })
            except Exception as error:  # a malformed connection is not fatal
                print("  direct listener: %s" % error)
            finally:
                conn.close()

    def stop(self):
        self.stopping = True
        try:
            self.sock.close()
        except OSError:
            pass


class ConnectProxy(threading.Thread):
    """A CONNECT relay that records the ClientHello inside the tunnel.

    The tunnel is then forwarded untouched, so whatever the app asked for
    (tls.peet.ws) completes for real and the server's report is genuine.
    """

    def __init__(self, port, recorder):
        threading.Thread.__init__(self)
        self.daemon = True
        self.port = port
        self.recorder = recorder
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # A previous run's socket can still be closing when the next cell
        # starts; retry briefly instead of failing the whole capture.
        for attempt in range(20):
            try:
                self.sock.bind(("0.0.0.0", port))
                break
            except OSError:
                if attempt == 19:
                    raise
                time.sleep(0.5)
        self.sock.listen(16)
        self.sock.settimeout(1.0)
        self.stopping = False

    def run(self):
        while not self.stopping:
            try:
                conn, peer = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self.handle, args=(conn, peer)).start()

    def handle(self, conn, peer):
        try:
            conn.settimeout(15)
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                head += chunk
            request, _, rest = head.partition(b"\r\n\r\n")
            first = request.split(b"\r\n")[0].decode("ascii", "replace")
            method, target, _ = first.split(" ")
            if method != "CONNECT" or ":" not in target:
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                return
            host, port = target.rsplit(":", 1)
            upstream = socket.create_connection((host, int(port)), timeout=15)
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

            record, rest = read_hello(conn, prefix=rest)
            if record:
                self.recorder.add(record, {
                    "peer": "%s:%d" % peer, "via": "CONNECT " + target,
                })
            # Forward the captured hello together with anything that followed
            # it, then relay both directions at once: a sequential pump would
            # leave the server's reply unread while we wait on the client.
            upstream.sendall((record or b"") + rest)
            back = threading.Thread(target=self.pump, args=(upstream, conn))
            back.start()
            self.pump(conn, upstream)
            back.join(timeout=20)
            upstream.close()
        except Exception as error:
            print("  proxy: %s" % error)
        finally:
            conn.close()

    @staticmethod
    def pump(source, sink):
        try:
            source.settimeout(20)
            while True:
                data = source.recv(16384)
                if not data:
                    break
                sink.sendall(data)
        except OSError:
            pass
        finally:
            try:
                sink.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def stop(self):
        self.stopping = True
        try:
            self.sock.close()
        except OSError:
            pass


def adb(serial, *args, **kwargs):
    command = ["adb"]
    if serial:
        command += ["-s", serial]
    command += list(args)
    return subprocess.run(command, capture_output=True, text=True,
                          timeout=kwargs.get("timeout", 120))


def device_facts(serial):
    """What the device says it is, so a capture never has to be described
    from memory. A container reports redroid* and its own fingerprint."""
    props = {
        "release": "ro.build.version.release",
        "sdk": "ro.build.version.sdk",
        "model": "ro.product.model",
        "abi": "ro.product.cpu.abi",
        "fingerprint": "ro.build.fingerprint",
    }
    facts = {}
    for key, prop in props.items():
        result = adb(serial, "shell", "getprop", prop)
        facts[key] = result.stdout.strip()
    webview = adb(serial, "shell", "dumpsys", "webviewupdate")
    match = re.search(r"Current WebView package \(name, version\): \((\S+), (\S+)\)",
                      webview.stdout)
    facts["webview"] = match.group(2) if match else ""
    return facts


def describe_device(facts):
    return "%s, Android %s (SDK %s), %s, WebView %s" % (
        facts["model"], facts["release"], facts["sdk"], facts["abi"],
        facts["webview"] or "unknown")


def host_ip():
    """The address the phone can reach us on, from the default route."""
    for args in (["route", "-n", "get", "default"], ["ip", "route", "get", "1.1.1.1"]):
        try:
            text = subprocess.run(args, capture_output=True, text=True,
                                  timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        match = re.search(r"interface:\s*(\S+)", text) or \
            re.search(r"dev\s+(\S+)", text)
        if not match:
            continue
        interface = match.group(1)
        probe = "ifconfig" if args[0] == "route" else "ip"
        if probe == "ifconfig":
            address = subprocess.run(["ipconfig", "getifaddr", interface],
                                     capture_output=True, text=True).stdout.strip()
        else:
            listing = subprocess.run(["ip", "-4", "addr", "show", interface],
                                     capture_output=True, text=True).stdout
            found = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", listing)
            address = found.group(1) if found else ""
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", address):
            return address
    raise SystemExit("could not work out this host's address; pass --host-ip")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL"))
    parser.add_argument("--out", default="phone-captures")
    parser.add_argument("--apk", default=os.path.join(HERE, "android_phone", "app.apk"))
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--proxy-port", type=int, default=8888)
    parser.add_argument("--host-ip")
    parser.add_argument("--reverse", action="store_true",
                        help="use adb reverse; the phone talks to its own "
                             "loopback instead of this machine's LAN address")
    parser.add_argument("--echo", action="store_true",
                        help="also fetch tls.peet.ws through the CONNECT proxy")
    parser.add_argument("--seconds", type=int, default=45)
    parser.add_argument("--label", default="capture",
                        help="SNI label prefix, e.g. okhttp-4-12-0")
    parser.add_argument("--mode", default="urlconn,webview",
                        help="comma-separated stacks: urlconn, webview, "
                             "okhttp, conscrypt, cronet")
    parser.add_argument("--record", help="compare with this library record")
    parser.add_argument("--no-install", action="store_true")
    args = parser.parse_args()
    # A label becomes a DNS name, so keep it to what sslip.io accepts.
    args.label = re.sub(r"[^A-Za-z0-9-]+", "-", args.label).strip("-")
    if not args.label:
        raise SystemExit("empty --label")

    if args.reverse:
        # The phone sees only its own loopback, and adb carries the
        # connection back here. 127-0-0-1.sslip.io resolves to 127.0.0.1 on
        # the phone, so the SNI labels still work and no LAN address is used.
        address = "127.0.0.1"
        ports = [args.port] + ([args.proxy_port] if args.echo else [])
        for port in ports:
            reverse = adb(args.serial, "reverse", "tcp:%d" % port,
                          "tcp:%d" % port)
            if reverse.returncode != 0:
                raise SystemExit("adb reverse failed: " + reverse.stderr.strip())
    else:
        address = args.host_ip or host_ip()
    # sslip.io turns the dotted address into a name that resolves back to it.
    base = address.replace(".", "-") + ".sslip.io"
    print("host %s, phone will use %s-*.<base>" % (address, args.label))
    print("mode: %s" % args.mode)

    facts = device_facts(args.serial)
    print("device: %s" % describe_device(facts))
    print("        %s" % facts["fingerprint"])

    recorder = Recorder(args.out)
    recorder.device = describe_device(facts)
    recorder.fingerprint = facts["fingerprint"]
    recorder.label = args.label
    recorder.stacks = args.mode
    direct = DirectListener(args.port, recorder)
    direct.start()
    proxy = None
    if args.echo:
        proxy = ConnectProxy(args.proxy_port, recorder)
        proxy.start()
    print("listening on %d%s" % (args.port,
                                 ", proxy on %d" % args.proxy_port if proxy else ""))

    try:
        if not args.no_install:
            result = adb(args.serial, "install", "-r", "-t", args.apk)
            if result.returncode != 0:
                raise SystemExit("install failed: " + result.stderr.strip())
        adb(args.serial, "logcat", "-c")
        adb(args.serial, "shell", "am", "force-stop", PACKAGE)
        start_args = ["shell", "am", "start", "-n", ACTIVITY,
                      "--es", "base", base, "--ei", "port", str(args.port),
                      "--es", "label", args.label, "--es", "mode", args.mode]
        # An empty `--es proxy ""` loses its value in adb's shell quoting,
        # and `am` then fails with "Argument expected after proxy".
        if args.echo:
            start_args += ["--es", "proxy", "%s:%d" % (address, args.proxy_port)]
        start = adb(args.serial, *start_args)
        if start.returncode != 0:
            raise SystemExit("launch failed: " + start.stderr.strip())
        time.sleep(args.seconds)
        log = adb(args.serial, "logcat", "-d", "-s", "PhoneCap:I")
    finally:
        direct.stop()
        if proxy:
            proxy.stop()
        if args.reverse:
            for port in (args.port, args.proxy_port):
                adb(args.serial, "reverse", "--remove", "tcp:%d" % port)

    # Diagnostic only: with --echo the phone's own report comes back inside
    # this log, including its public egress address. Keep it out of the repo.
    if log.returncode == 0 and log.stdout.strip():
        with open(os.path.join(args.out, "app.log"), "w", encoding="utf-8") as handle:
            handle.write(log.stdout)

    print("\n%d ClientHello(s) captured into %s" % (len(recorder.entries), args.out))
    for entry in recorder.entries:
        print("  %-38s %s" % (entry["sni"], entry["tls"]["ja4"]))

    if args.record:
        return compare(args.record, recorder.entries)
    return 0


def compare(record_name, entries):
    """Diff a capture against one record, naming the stack it belongs to."""
    library = json.load(open(os.path.join(
        HERE, "..", "..", "src", "fingerprint", "builtin.json")))
    record = next((r for r in library["fingerprints"]
                   if r["name"] == record_name), None)
    if record is None:
        raise SystemExit("no record named " + record_name)
    expected = record["tls"]
    expected_ciphers = [c for c in expected["ciphers"].split(":") if c]
    expected_extensions = [e["name"].split(" (")[0]
                           for e in json.load(open(os.path.join(
                               HERE, "raw", record_name + ".json")))["tls"]["extensions"]]

    def bare(names):
        return [n.rstrip("s") for n in names]

    for entry in entries:
        live_ciphers = [c for c in entry["tls"]["ciphers"] if "GREASE" not in c]
        live_extensions = [e["name"].split(" (")[0] for e in entry["tls"]["extensions"]]
        if (live_ciphers == [c for c in expected_ciphers if "GREASE" not in c]
                and bare(live_extensions) == bare(expected_extensions)):
            print("\nOK: %s matches %s" % (record_name, entry["sni"]))
            return 0
    print("\nno capture matches %s" % record_name)
    for entry in entries:
        print("  %-38s %s" % (entry["sni"], entry["tls"]["ja4"]))
    print("  record ja4: %s" % expected.get("ja4"))
    return 1


if __name__ == "__main__":
    sys.exit(main())
