'use strict';

// Tests for the Node binding. They use the standard library's test runner
// (`node --test`) and the offline echo server, so they need no network.
//
//   python3 ../../../../rust-curl-impersonate-skills/skills/rust-curl-impersonate-native/scripts/local_echo_server.py 8765 &
//   RCI_LIB=/path/to/lib/librust_curl_impersonate_ffi.so node --test

const test = require('node:test');
const assert = require('node:assert');
const { Rci } = require('./rci');

const BASE = process.env.RCI_BASE || 'http://127.0.0.1:8765';
const rci = Rci.load();

test('the ABI reports version 2 or newer', () => {
  assert.ok(rci.abiVersion >= 2, `ABI ${rci.abiVersion}`);
});

test('48 presets and more profiles than presets', () => {
  const targets = rci.targets();
  assert.strictEqual(targets.length, 48);
  const profiles = rci.profiles();
  assert.ok(profiles.length > targets.length);
  for (const name of targets) assert.ok(profiles.includes(name), name);
});

test('profile metadata names the client family', () => {
  const info = rci.profileInfo('chrome150');
  assert.strictEqual(info.family, 'chrome');
  assert.strictEqual(info.has_http3, true);
  assert.strictEqual(info.fidelity, null);
  assert.throws(() => rci.profileInfo('definitely-not-a-profile'), /unknown profile/);
});

test('a GET returns the body and the negotiated protocol', () => {
  const client = rci.client('chrome150');
  try {
    const reply = client.get(`${BASE}/index.html`);
    assert.strictEqual(reply.status, 200);
    assert.strictEqual(reply.body, 'hello from rust-curl-impersonate');
    assert.strictEqual(reply.body_is_text, true);
    assert.ok(['HTTP/1.1', 'HTTP/2.0'].includes(reply.version), reply.version);
    const contentType = reply.headers.find(([name]) => name.toLowerCase() === 'content-type');
    assert.ok(contentType && contentType[1].includes('text/plain'));
  } finally {
    client.close();
  }
});

test('a binary body arrives as hex', () => {
  const reply = rci.get('chrome150', `${BASE}/rci-smoke.bin`);
  assert.strictEqual(reply.body_is_text, false);
  const bytes = Buffer.from(reply.body, 'hex');
  assert.strictEqual(bytes.toString('binary'), '\x00\x01\x02\xff\xfe binary');
});

test('per-request headers reach the server', () => {
  const client = rci.client('chrome150');
  try {
    const reply = client.requestWithHeaders('POST', `${BASE}/echo`, [['x-marker', 'node']], '{"a":1}');
    const echoed = JSON.parse(reply.body);
    assert.strictEqual(echoed.headers['x-marker'], 'node');
    assert.strictEqual(echoed.body, '{"a":1}');
  } finally {
    client.close();
  }
});

test('an unknown option is refused before a request is sent', () => {
  assert.throws(() => rci.client('chrome150', { timeoutms: 1000 }), /unknown option/);
  const client = rci.client('chrome150', { timeoutMs: 5000, headers: [['accept-language', 'zh-CN']] });
  client.close();
});

test('a redirect is returned, not followed, by default', () => {
  const reply = rci.get('chrome150', `${BASE}/redirect`);
  assert.strictEqual(reply.status, 302);
  const location = reply.headers.find(([name]) => name.toLowerCase() === 'location');
  assert.ok(location, 'Location header');
});

test('follow_safe follows and refuses a loopback hop', () => {
  const client = rci.client('chrome150', { followSafe: true });
  try {
    assert.throws(() => client.get(`${BASE}/redirect`), /blocked/);
  } finally {
    client.close();
  }
});

test('one handle carries the cookie jar between requests', () => {
  const client = rci.client('chrome150');
  try {
    client.get(`${BASE}/cookie`);
    const reply = client.get(`${BASE}/echo`);
    const echoed = JSON.parse(reply.body);
    assert.ok(String(echoed.headers.cookie).includes('sid=abc123'), reply.body);
    const activity = client.activity();
    assert.ok(activity.cookies.length >= 1);
  } finally {
    client.close();
  }
});

test('wire profile and last headers are introspectable', () => {
  const client = rci.client('python3.12_requests');
  try {
    assert.strictEqual(client.wireProfile(), 'python3.12_requests');
    client.get(`${BASE}/index.html`);
    const headers = client.lastHeaders();
    assert.ok(headers.length > 0);
  } finally {
    client.close();
  }
});

test('a closed client refuses further requests', () => {
  const client = rci.client('chrome150');
  client.close();
  assert.throws(() => client.get(`${BASE}/index.html`), /closed/);
});

test('a record can be registered at run time', () => {
  rci.loadFingerprints('[{"name":"node_test_client","extends":"chrome150","family":"chrome","platform":"linux"}]');
  assert.strictEqual(rci.profileInfo('node_test_client').wire, 'chrome150');
  assert.throws(
    () => rci.loadFingerprints('[{"name":"node_bad","tls":{"ciphers":"NOT_A_CIPHER"}}]'),
    /NO_CIPHER_MATCH/,
  );
});

test('http1_only forces HTTP/1.1 against a public site', { skip: !process.env.RCI_NETWORK }, async () => {
  const client = rci.client('chrome150', { http1Only: true });
  try {
    const reply = client.get('https://example.com/');
    assert.strictEqual(reply.version, 'HTTP/1.1');
  } finally {
    client.close();
  }
});
