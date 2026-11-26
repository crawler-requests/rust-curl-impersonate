"""ctypes binding for the rust-curl-impersonate C ABI (ABI version 2).

Copy this file into your project next to the library archive, or install it
from the archive's ``python/`` directory. It has no third-party dependencies.

    from rci_bindings import Client

    with Client("chrome150") as client:
        reply = client.get("https://tls.peet.ws/api/all")
        print(reply.status, reply.version, reply.headers["server"])

Design notes, all of them forced by the C ABI:

- Every ``char *`` the library returns is owned by it and is released with
  ``rci_string_free``. Those returns are declared ``c_void_p`` here, never
  ``c_char_p``: ctypes copies a ``c_char_p`` result and drops the original
  pointer, so freeing it would release an address the library never handed out.
- ``rci_last_error`` returns ``const char *`` that the caller must *not*
  release, so it stays ``c_char_p``.
- The client handle is an opaque ``RciClient *``; one handle per thread.
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import sys
from typing import Any, Iterable, Mapping, Sequence, Optional

ABI_VERSION = 2

# File name of the shared library per platform.
LIB_NAMES = {
    "linux": "librust_curl_impersonate_ffi.so",
    "darwin": "librust_curl_impersonate_ffi.dylib",
    "win32": "rust_curl_impersonate_ffi.dll",
}


class RciError(RuntimeError):
    """An operation the C ABI reported as ``{"error": "..."}``."""


# ---------------------------------------------------------------------------
# Signature parsing: read rci.h so the ctypes declarations cannot drift.
# ---------------------------------------------------------------------------

# C spelling -> ctypes type, used for both arguments and results. Pointers are
# handled by the rules in `_argument_type` / `_result_type` because ownership
# differs between an argument and a result.
_CTYPES = {
    "void": None,
    "uint32_t": ctypes.c_uint32,
    "uint16_t": ctypes.c_uint16,
    "int": ctypes.c_int,
    "size_t": ctypes.c_size_t,
    "bool": ctypes.c_bool,
}

_PROTOTYPE = re.compile(
    r"^\s*"                                   # start of a declaration
    # Return type: "uint32_t", "char *", "RciClient *", "const char *", ...
    # `char *rci_targets` has no space between the star and the name, so the
    # separator after the star has to be optional.
    r"(?P<ret>(?:const\s+)?\w+(?:\s+\w+)*\s*\*?)"
    r"(?:\s+|\s*)"
    r"(?P<name>rci_[a-z0-9_]+)"                # function name
    r"\s*\((?P<params>[^;{}]*)\)\s*;",        # parameter list
    re.MULTILINE,
)


def _split_params(params: str) -> list[str]:
    params = params.strip()
    if not params or params == "void":
        return []
    return [part.strip() for part in params.split(",")]


_PARAM_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\s*$")


def _parameter_spelling(part: str) -> str:
    """Drop the parameter name from a C parameter declaration.

    `RciClient *handle` becomes `RciClient *`; `const uint8_t *body` becomes
    `const uint8_t *`. The pointer star belongs to the type.
    """
    spelling = " ".join(part.split())
    match = _PARAM_NAME.search(spelling)
    if match is None:
        raise ValueError(f"cannot read parameter {part!r}")
    return spelling[: match.start()].strip()


def _argument_type(spelling: str) -> Any:
    spelling = " ".join(spelling.split())
    if spelling in _CTYPES:
        return _CTYPES[spelling]
    if spelling.startswith("const ") and spelling.endswith(" *"):
        inner = spelling[len("const "): -2].strip()
        if inner == "char":
            return ctypes.c_char_p
        if inner == "uint8_t":
            return ctypes.c_void_p          # a buffer; pass an array or a void*
        return ctypes.c_void_p
    if spelling.endswith(" *"):
        return ctypes.c_void_p              # RciClient *, char * (input)
    raise ValueError(f"unsupported C parameter type {spelling!r}")


def _result_type(spelling: str) -> Any:
    spelling = " ".join(spelling.split())
    if spelling in _CTYPES:
        return _CTYPES[spelling]
    if spelling.startswith("const ") and spelling.endswith(" *"):
        # `const char *rci_last_error` is borrowed by the caller and must not
        # be freed, so a c_char_p result (a copy) is the right type here.
        return ctypes.c_char_p
    if spelling.endswith(" *"):
        # `char *` results are owned by the library: keep the raw pointer.
        return ctypes.c_void_p
    raise ValueError(f"unsupported C return type {spelling!r}")


def parse_header(text: str) -> dict[str, tuple[Any, list[Any], bool]]:
    """Return {name: (restype, argtypes, returns_owned_string)} from rci.h.

    `returns_owned_string` is true for `char *` results, which a caller must
    release with ``rci_string_free``.
    """
    functions: dict[str, tuple[Any, list[Any], bool]] = {}
    for match in _PROTOTYPE.finditer(text):
        name = match.group("name")
        ret = " ".join(match.group("ret").split())
        argtypes = [
            _argument_type(_parameter_spelling(part))
            for part in _split_params(match.group("params"))
        ]
        owned = ret == "char *" or ret.startswith("char ")
        functions[name] = (_result_type(ret), argtypes, owned)
    return functions


# Fallback table, identical to rci.h. Used only when the header is not next to
# the library (a copied .so with no include/ directory). `_check_header` in the
# tests keeps the two in step.
_BUILTIN_SIGNATURES = {
    "rci_version": (ctypes.c_uint32, [], False),
    "rci_targets": (ctypes.c_void_p, [], True),
    "rci_profiles": (ctypes.c_void_p, [], True),
    "rci_profile_info": (ctypes.c_void_p, [ctypes.c_char_p], True),
    "rci_client_new": (ctypes.c_void_p, [ctypes.c_char_p], False),
    "rci_client_new_with_options": (
        ctypes.c_void_p,
        [ctypes.c_char_p, ctypes.c_char_p],
        False,
    ),
    "rci_client_free": (None, [ctypes.c_void_p], False),
    "rci_client_profile": (ctypes.c_void_p, [ctypes.c_void_p], True),
    "rci_request": (
        ctypes.c_void_p,
        [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t],
        True,
    ),
    "rci_request_with": (
        ctypes.c_void_p,
        [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p],
        True,
    ),
    "rci_get": (ctypes.c_void_p, [ctypes.c_char_p, ctypes.c_char_p], True),
    "rci_http3_get": (
        ctypes.c_void_p,
        [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p],
        True,
    ),
    "rci_client_last_headers": (ctypes.c_void_p, [ctypes.c_void_p], True),
    "rci_client_activity": (ctypes.c_void_p, [ctypes.c_void_p], True),
    "rci_load_fingerprints": (ctypes.c_void_p, [ctypes.c_char_p], True),
    "rci_last_error": (ctypes.c_char_p, [], False),
    "rci_string_free": (None, [ctypes.c_void_p], False),
}


def library_name() -> str:
    if sys.platform == "darwin":
        return LIB_NAMES["darwin"]
    if os.name == "nt":
        return LIB_NAMES["win32"]
    return LIB_NAMES["linux"]


def _candidate_dirs() -> list[str]:
    here = os.path.abspath(os.path.dirname(__file__))
    # In a release archive this file sits at <root>/python/, next to lib/ and
    # include/. Inside the repository it sits at bindings/ffi/python/, so the
    # build output is three levels up.
    return [
        os.path.join(here, "..", "lib"),
        os.path.join(here, "lib"),
        os.path.join(here, "..", "..", "..", "target", "release"),
        here,
    ]


def find_library(path: Optional[str] = None) -> tuple[str, Optional[str]]:
    """Locate the shared library. Returns (library path, rci.h path or None).

    `path` wins; then $RCI_LIB; then the release-archive layout, then a
    `cargo build` inside the repository.
    """
    name = library_name()
    explicit = path or os.environ.get("RCI_LIB")
    if explicit:
        if os.path.isdir(explicit):
            explicit = os.path.join(explicit, name)
        if not os.path.exists(explicit):
            raise FileNotFoundError(f"no shared library at {explicit}")
        header = _header_next_to(explicit)
        return explicit, header
    for directory in _candidate_dirs():
        candidate = os.path.join(directory, name)
        if os.path.exists(candidate):
            return candidate, _header_next_to(candidate)
    raise FileNotFoundError(
        f"{name} not found; set RCI_LIB or pass Library(path=...). Searched: "
        + ", ".join(_candidate_dirs())
    )


def _header_next_to(library: str) -> Optional[str]:
    root = os.path.dirname(os.path.abspath(library))
    here = os.path.abspath(os.path.dirname(__file__))
    for candidate in (
        os.path.join(root, "include", "rci.h"),
        os.path.join(root, "..", "include", "rci.h"),
        os.path.join(root, "rci.h"),
        os.path.join(root, "..", "rci.h"),
        # A `cargo build` inside the repository: the header is next to the
        # binding crate, not next to target/release/.
        os.path.join(here, "..", "rci.h"),
        os.path.join(here, "..", "..", "..", "include", "rci.h"),
    ):
        if os.path.exists(candidate):
            return os.path.normpath(candidate)
    return None


# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------


class Library:
    """The loaded shared library, with ctypes signatures applied to all 17 functions.

    `path` accepts a library file, the archive's `lib/` directory, or a
    directory containing both the library and `include/rci.h`.
    """

    def __init__(self, path: Optional[str] = None, loader: Any = None) -> None:
        library_path, header = find_library(path)
        self.path = library_path
        self.header = header
        self.dll = (loader or ctypes.CDLL)(library_path)
        self.signatures = parse_header(open(header, encoding="utf-8").read()) \
            if header else dict(_BUILTIN_SIGNATURES)
        self._bind()
        self.check_abi()

    def _bind(self) -> None:
        """Apply a signature to every function the header declares.

        The header is the source of truth, so a function it declares but the
        loaded library does not export is a version mismatch worth refusing
        now, not an AttributeError on the caller's first request.
        """
        missing = []
        for name, (restype, argtypes, _owned) in self.signatures.items():
            try:
                function = getattr(self.dll, name)
            except AttributeError:
                missing.append(name)
                continue
            function.restype = restype
            function.argtypes = argtypes
        if missing:
            raise RciError(
                f"library at {self.path} does not export: {', '.join(sorted(missing))}"
            )

    def check_abi(self) -> None:
        """Refuse to run against a library with a different ABI generation."""
        version = self.dll.rci_version()
        if version < ABI_VERSION:
            raise RciError(
                f"library at {self.path} has ABI {version}, this binding needs "
                f"{ABI_VERSION} or newer"
            )

    # -- string ownership ---------------------------------------------------
    def _take(self, pointer: Optional[int]) -> Any:
        """Read a JSON string the library returned, then release it."""
        if not pointer:
            raise RciError("library returned a null string")
        try:
            return json.loads(ctypes.string_at(pointer).decode("utf-8"))
        finally:
            self.dll.rci_string_free(pointer)

    def _take_text(self, pointer: Optional[int]) -> str:
        if not pointer:
            raise RciError("library returned a null string")
        try:
            return ctypes.string_at(pointer).decode("utf-8")
        finally:
            self.dll.rci_string_free(pointer)

    def _last_error(self) -> str:
        text = self.dll.rci_last_error()
        return text.decode("utf-8") if text else "unknown error"

    # -- library-wide queries ----------------------------------------------
    @property
    def version(self) -> int:
        return int(self.dll.rci_version())

    def targets(self) -> list[str]:
        """The 48 curl-impersonate preset names."""
        return self._take(self.dll.rci_targets())

    def profiles(self) -> list[str]:
        """Every selectable name: presets plus fingerprint-library records."""
        return self._take(self.dll.rci_profiles())

    def profile_info(self, name: str) -> dict[str, Any]:
        reply = self._take(self.dll.rci_profile_info(name.encode()))
        if "error" in reply:
            raise RciError(reply["error"])
        return reply

    def profile(self, name: str) -> "Profile":
        return Profile(name, self.profile_info(name))

    # -- clients ------------------------------------------------------------
    def client(self, profile: str, **options: Any) -> "Client":
        return Client(profile, library=self, **options)

    def get(self, profile: str, url: str) -> "Response":
        return Response(self._take(self.dll.rci_get(profile.encode(), url.encode())), self)

    def http3_get(self, profile: str, addr: str, host: str, path: str) -> "Response":
        reply = self._take(
            self.dll.rci_http3_get(
                profile.encode(), addr.encode(), host.encode(), path.encode()
            )
        )
        return Response(reply, self)

    def load_fingerprints(self, document: Any) -> None:
        """Register a library-schema document for this process.

        `document` is JSON text, one record (dict), or a list of records.
        """
        if isinstance(document, (dict, list)):
            text = json.dumps(document)
        else:
            text = str(document)
        reply = self._take(self.dll.rci_load_fingerprints(text.encode()))
        if "error" in reply:
            raise RciError(reply["error"])


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class Client:
    """One profile's handle. Not thread-safe: one handle per thread.

    Keyword arguments become `rci_client_new_with_options` options and are
    validated by the library (an unknown key raises `RciError`):

        Client("chrome150", timeout_ms=10_000,
               headers=[("accept-language", "zh-CN")],
               follow_safe=True, proxy="socks5://127.0.0.1:1080")
    """

    def __init__(self, profile: str, library: Optional[Library] = None, **options: Any) -> None:
        self._lib = library or default_library()
        self.profile = profile
        payload = _options_json(options)
        handle = self._lib.dll.rci_client_new_with_options(
            profile.encode(), payload.encode() if payload else None
        )
        if not handle:
            raise RciError(self._lib._last_error())
        self._handle: Optional[int] = handle

    # -- requests -----------------------------------------------------------
    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Iterable[Sequence[str]]] = None,
        body: Optional[bytes | str] = None,
    ) -> "Response":
        """Send one request. `headers` is an iterable of (name, value) pairs.

        The ABI has two request functions: `rci_request` takes a
        length-delimited byte body, `rci_request_with` takes per-request
        headers and a NUL-terminated string body. Per-request headers together
        with a binary body is the one combination neither covers, so it is
        refused here rather than silently dropping the body.
        """
        self._check()
        if headers and isinstance(body, (bytes, bytearray)) and body:
            raise ValueError(
                "per-request headers with a binary body is not in the C ABI; "
                "use Client.request_with_headers (string body) or send the "
                "bytes without headers"
            )
        if headers or isinstance(body, str):
            return self.request_with_headers(method, url, headers, body)
        raw = body
        buffer = None
        if raw:
            buffer = ctypes.create_string_buffer(raw, len(raw))
        pointer = self._lib.dll.rci_request(
            self._handle,
            method.encode(),
            url.encode(),
            ctypes.cast(buffer, ctypes.c_void_p) if buffer else None,
            len(raw) if raw else 0,
        )
        return Response(self._lib._take(pointer), self._lib)

    def get(self, url: str, headers: Optional[Iterable[Sequence[str]]] = None) -> "Response":
        return self.request("GET", url, headers=headers)

    def post(
        self,
        url: str,
        body: bytes | str,
        headers: Optional[Iterable[Sequence[str]]] = None,
    ) -> "Response":
        return self.request("POST", url, headers=headers, body=body)

    def request_with_headers(
        self, method: str, url: str, headers: Optional[Iterable[Sequence[str]]],
        body: Optional[bytes | str] = None,
    ) -> "Response":
        """`rci_request_with`: per-request headers, NUL-terminated string body."""
        headers_json = json.dumps(list(headers)) if headers else None
        text = body.decode("utf-8") if isinstance(body, (bytes, bytearray)) else body
        self._check()
        pointer = self._lib.dll.rci_request_with(
            self._handle, method.encode(), url.encode(),
            headers_json.encode() if headers_json is not None else None,
            text.encode() if text is not None else None,
        )
        return Response(self._lib._take(pointer), self._lib)

    # -- introspection -------------------------------------------------------
    def last_headers(self) -> list[list[str]]:
        self._check()
        return self._lib._take(self._lib.dll.rci_client_last_headers(self._handle))

    def activity(self) -> dict[str, list[str]]:
        self._check()
        return self._lib._take(self._lib.dll.rci_client_activity(self._handle))

    def wire_profile(self) -> str:
        """The preset whose bytes this handle sends."""
        self._check()
        return self._lib._take_text(self._lib.dll.rci_client_profile(self._handle))

    # -- lifecycle ------------------------------------------------------------
    def _check(self) -> None:
        if not self._handle:
            raise RciError("client is closed")

    def close(self) -> None:
        if self._handle:
            self._lib.dll.rci_client_free(self._handle)
            self._handle = None

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    def __del__(self) -> None:
        # Best effort: a handle outliving the interpreter is not worth crashing over.
        try:
            self.close()
        except Exception:
            pass


def _options_json(options: Mapping[str, Any]) -> str:
    if not options:
        return ""
    payload = {}
    for key, value in options.items():
        if key == "headers" and value:
            payload["headers"] = [[str(n), str(v)] for n, v in value]
        else:
            payload[key] = value
    return json.dumps(payload)


# ---------------------------------------------------------------------------
# Profile and Response
# ---------------------------------------------------------------------------


class Profile:
    """Metadata from `rci_profile_info`, with attributes for each field."""

    def __init__(self, name: str, info: Mapping[str, Any]) -> None:
        self.name = name
        self.info = dict(info)

    def __getattr__(self, item: str) -> Any:
        try:
            return self.info[item]
        except KeyError as error:
            raise AttributeError(item) from error

    def __repr__(self) -> str:
        return f"Profile({self.name!r}, family={self.info.get('family')!r})"


class Response:
    """A response JSON object. `content` decodes the hex form of a binary body."""

    def __init__(self, reply: Mapping[str, Any], library: Library) -> None:
        self.raw = dict(reply)
        self._lib = library
        if "error" in reply:
            raise RciError(str(reply["error"]))

    _FIELDS = ("status", "version", "url", "headers", "body", "body_is_text")

    def __getattr__(self, item: str) -> Any:
        if item in Response._FIELDS:
            if item not in self.raw:
                raise AttributeError(item)
            return self.raw[item]
        raise AttributeError(item)

    def __repr__(self) -> str:
        return f"Response(status={self.raw.get('status')}, version={self.raw.get('version')!r})"

    @property
    def ok(self) -> bool:
        return 200 <= int(self.raw.get("status", 0)) < 300

    @property
    def body_is_text(self) -> bool:
        return bool(self.raw.get("body_is_text", True))

    @property
    def text(self) -> str:
        """The body as text. Raises when the body is binary; use `content`."""
        if not self.body_is_text:
            raise ValueError("binary body; use Response.content")
        return self.raw.get("body", "")

    @property
    def content(self) -> bytes:
        """The body as bytes, decoding the hex form when `body_is_text` is false."""
        if self.body_is_text:
            return self.raw.get("body", "").encode("utf-8")
        return bytes.fromhex(self.raw.get("body", ""))

    def header(self, name: str) -> Optional[str]:
        """First value of `name` (case-insensitive), or None."""
        lowered = name.lower()
        for key, value in self.raw.get("headers", []):
            if key.lower() == lowered:
                return value
        return None

    @property
    def header_names(self) -> list[str]:
        return [key for key, _ in self.raw.get("headers", [])]

    def json(self) -> Any:
        """Parse the body as JSON (text bodies only)."""
        return json.loads(self.text)


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

_DEFAULT: Optional[Library] = None


def default_library(path: Optional[str] = None) -> Library:
    """The process-wide Library, loaded on first use (or `path`)."""
    global _DEFAULT
    if path is not None:
        return Library(path)
    if _DEFAULT is None:
        _DEFAULT = Library()
    return _DEFAULT


def version() -> int:
    return default_library().version


def profile_info(name: str) -> dict[str, Any]:
    return default_library().profile_info(name)


def load_fingerprints(document: Any) -> None:
    default_library().load_fingerprints(document)


def get(profile: str, url: str) -> Response:
    """One-shot GET: builds a client, sends, frees."""
    return default_library().get(profile, url)
