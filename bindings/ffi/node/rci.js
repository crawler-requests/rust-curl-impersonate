'use strict';

// A Node binding for the rust-curl-impersonate C ABI (ABI v2), on top of koffi
// (or ffi-napi, which exposes the same `ffi.Library` shape closely enough that
// the declaration below is translatable).
//
// The library is opened at run time, so `npm install` does not need native
// build tools; koffi ships a prebuilt binary.
//
//     const { Rci } = require('./rci');
//     const rci = Rci.load();                 // RCI_LIB, then lib/
//     const client = rci.client('chrome150');
//     const reply = client.get('https://tls.peet.ws/api/all');
//     console.log(reply.status, reply.version);
//     client.close();

const fs = require('fs');
const os = require('os');
const path = require('path');

const LIB_NAMES = {
  darwin: 'librust_curl_impersonate_ffi.dylib',
  win32: 'rust_curl_impersonate_ffi.dll',
  linux: 'librust_curl_impersonate_ffi.so',
};
const ABI_VERSION = 2;

function libraryName() {
  return LIB_NAMES[process.platform] || LIB_NAMES.linux;
}

// candidatePaths covers both layouts the library ships in: the release archive
// (lib/ beside this file) and a `cargo build` inside the repository
// (target/release three directories up).
function candidatePaths() {
  const here = __dirname;
  const name = libraryName();
  const from = (dir) => path.join(dir, name);
  return [
    process.env.RCI_LIB || '',
    process.env.RCI_LIB_DIR ? from(process.env.RCI_LIB_DIR) : '',
    from(path.join(here, 'lib')),
    from(path.join(here, '..', 'lib')),
    from(path.join(here, '..', '..', '..', 'target', 'release')),
    from(path.join(process.cwd(), 'lib')),
    from(process.cwd()),
  ].filter(Boolean);
}

function resolveLibrary(explicit) {
  if (explicit) {
    const info = fs.existsSync(explicit) && fs.statSync(explicit);
    if (info && info.isDirectory()) {
      explicit = path.join(explicit, libraryName());
    }
    if (!fs.existsSync(explicit)) {
      throw new Error(`no shared library at ${explicit}`);
    }
    return explicit;
  }
  for (const candidate of candidatePaths()) {
    if (fs.existsSync(candidate)) return candidate;
  }
  throw new Error(
    `${libraryName()} not found; set RCI_LIB or RCI_LIB_DIR (looked in ${candidatePaths().join(', ')})`,
  );
}

// The 17 declarations, exactly as rci.h declares them. `char *` returns are
// declared `void *` so koffi hands back the raw pointer; declaring them `char *`
// would let koffi copy and drop it, and rci_string_free would then free memory
// the library never allocated for us.
const DECLARATIONS = {
  rci_version: ['uint32_t', []],
  rci_targets: ['void *', []],
  rci_profiles: ['void *', []],
  rci_profile_info: ['void *', ['const char *']],
  rci_client_new: ['void *', ['const char *']],
  rci_client_new_with_options: ['void *', ['const char *', 'const char *']],
  rci_client_free: ['void', ['void *']],
  rci_client_profile: ['void *', ['void *']],
  rci_request: ['void *', ['void *', 'const char *', 'const char *', 'const void *', 'size_t']],
  rci_request_with: ['void *', ['void *', 'const char *', 'const char *', 'const char *', 'const char *']],
  rci_get: ['void *', ['const char *', 'const char *']],
  rci_http3_get: ['void *', ['const char *', 'const char *', 'const char *', 'const char *']],
  rci_client_last_headers: ['void *', ['void *']],
  rci_client_activity: ['void *', ['void *']],
  rci_last_error: ['const char *', []],
  rci_load_fingerprints: ['void *', ['const char *']],
  rci_string_free: ['void', ['void *']],
};

class Rci {
  constructor(ffi, library, libraryPath) {
    this.ffi = ffi;
    this.libraryPath = libraryPath;
    this.fn = {};
    for (const [name, [returns, args]] of Object.entries(DECLARATIONS)) {
      this.fn[name] = library.func(`${returns} ${name}(${args.join(', ')})`);
    }
    const version = this.fn.rci_version();
    if (version < ABI_VERSION) {
      throw new Error(`library at ${libraryPath} reports ABI ${version}, this binding needs >= ${ABI_VERSION}`);
    }
    this.abiVersion = version;
  }

  static load(options = {}) {
    const { ffi, libraryPath } = options;
    const backend = ffi || require('koffi');
    const resolved = resolveLibrary(libraryPath);
    const library = backend.load(resolved);
    return new Rci(backend, library, resolved);
  }

  // decode reads a library-owned string and frees it. Every `char *` the ABI
  // returns is freed this way and only this way.
  decode(pointer) {
    if (!pointer) return '';
    const text = this.ffi.decode(pointer, 'char', -1);
    this.fn.rci_string_free(pointer);
    return text;
  }

  // decodeJSON is decode plus the one failure shape every query shares.
  decodeJSON(pointer, label) {
    const text = this.decode(pointer);
    let value;
    try {
      value = JSON.parse(text);
    } catch (error) {
      throw new Error(`${label}: library returned non-JSON (${text.slice(0, 120)})`);
    }
    if (value && typeof value === 'object' && typeof value.error === 'string') {
      throw new Error(value.error);
    }
    return value;
  }

  targets() {
    return this.decodeJSON(this.fn.rci_targets(), 'targets');
  }

  profiles() {
    return this.decodeJSON(this.fn.rci_profiles(), 'profiles');
  }

  profileInfo(name) {
    return this.decodeJSON(this.fn.rci_profile_info(name), 'profile_info');
  }

  // errorText reads rci_last_error, which is borrowed: never freed.
  errorText() {
    return this.fn.rci_last_error() || '';
  }

  // client creates a handle. `options` is a plain object mapped to the ABI's
  // option keys; an unknown key is refused by the library, and the typed field
  // list below is what keeps a typo from being expressed at all.
  client(profile, options) {
    const encoded = encodeOptions(options);
    const handle = encoded === null
      ? this.fn.rci_client_new(profile)
      : this.fn.rci_client_new_with_options(profile, encoded);
    if (!handle) {
      const message = this.errorText() || 'rci_client_new returned NULL';
      throw new Error(message);
    }
    return new Client(this, handle, profile);
  }

  get(profile, url) {
    return this.decodeJSON(this.fn.rci_get(profile, url), 'get');
  }

  http3Get(profile, addr, host, requestPath) {
    return this.decodeJSON(this.fn.rci_http3_get(profile, addr, host, requestPath), 'http3_get');
  }

  // loadFingerprints registers a library-schema JSON document for this process.
  // The whole document is validated first, so success means the records can be
  // sent. A name it shares with a built-in record resolves to this one.
  loadFingerprints(document) {
    this.decodeJSON(this.fn.rci_load_fingerprints(document), 'load_fingerprints');
    return true;
  }
}

// encodeOptions maps the typed option fields to the ABI's keys. Values that are
// `undefined` are left out so the library keeps its own default.
function encodeOptions(options) {
  if (!options) return null;
  const payload = {};
  const keys = [
    ['timeoutMs', 'timeout_ms'],
    ['proxy', 'proxy'],
    ['followRedirects', 'follow_redirects'],
    ['followSafe', 'follow_safe'],
    ['poolMaxIdlePerHost', 'pool_max_idle_per_host'],
    ['headers', 'headers'],
    ['splitCookies', 'split_cookies'],
    ['http1Only', 'http1_only'],
  ];
  for (const [field, key] of keys) {
    if (options[field] !== undefined) payload[key] = options[field];
  }
  const known = new Set(keys.map(([field]) => field));
  for (const field of Object.keys(options)) {
    if (!known.has(field)) {
      throw new Error(`unknown option ${field}; the ABI accepts ${[...known].join(', ')}`);
    }
  }
  return JSON.stringify(payload);
}

class Client {
  constructor(rci, handle, profile) {
    this.rci = rci;
    this.handle = handle;
    this.profile = profile;
    this.closed = false;
  }

  check() {
    if (this.closed || !this.handle) throw new Error('rci: client is closed');
  }

  // request sends a byte body. The method is sent verbatim: the ABI does not
  // validate it, so a typo reaches the server rather than failing here.
  request(method, url, body) {
    this.check();
    const payload = body === undefined || body === null ? null : Buffer.from(body);
    const pointer = payload
      ? this.rci.fn.rci_request(this.handle, method, url, payload, payload.length)
      : this.rci.fn.rci_request(this.handle, method, url, null, 0);
    const reply = this.rci.decodeJSON(pointer, 'request');
    keepAlive(payload);
    return reply;
  }

  // requestWithHeaders is the ABI's per-request-header path; its body is
  // NUL-terminated, so it cannot carry binary data.
  requestWithHeaders(method, url, headers, body) {
    this.check();
    const headersJSON = headers && headers.length ? JSON.stringify(headers) : null;
    const payload = typeof body === 'string' ? body : null;
    return this.rci.decodeJSON(
      this.rci.fn.rci_request_with(this.handle, method, url, headersJSON, payload),
      'request_with',
    );
  }

  get(url) {
    return this.request('GET', url, null);
  }

  post(url, body) {
    return this.requestWithHeaders('POST', url, null, body);
  }

  lastHeaders() {
    this.check();
    return this.rci.decodeJSON(this.rci.fn.rci_client_last_headers(this.handle), 'last_headers');
  }

  activity() {
    this.check();
    return this.rci.decodeJSON(this.rci.fn.rci_client_activity(this.handle), 'activity');
  }

  wireProfile() {
    this.check();
    return this.rci.decode(this.rci.fn.rci_client_profile(this.handle));
  }

  close() {
    if (this.closed) return;
    this.rci.fn.rci_client_free(this.handle);
    this.closed = true;
    this.handle = null;
  }
}

// keepAlive stops the collector from reusing the body buffer while the C side
// may still be reading it. koffi copies synchronously, but this documents the
// obligation and costs a macro task.
function keepAlive(value) {
  if (value !== null && value !== undefined) {
    setImmediate(() => value);
  }
}

module.exports = { Rci, Client, ABI_VERSION, libraryName, resolveLibrary, candidatePaths };
