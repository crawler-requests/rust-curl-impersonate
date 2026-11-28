<?php
/**
 * Tests for the PHP binding. Plain PHP, no PHPUnit: the binding has no
 * dependencies and neither do its checks.
 *
 *     python3 local_echo_server.py 8765 &
 *     RCI_LIB=/path/to/librust_curl_impersonate_ffi.so php tests.php
 *
 * Exit code 0 means every check held. The first block compares the inline FFI
 * declarations against rci.h, which is the one place PHP's cdef has to keep a
 * hand-maintained copy in step.
 */

require __DIR__ . '/rci.php';

$base = getenv('RCI_BASE') ?: 'http://127.0.0.1:8765';
$failures = [];
$checks = 0;

function check(string $label, bool $held, string $detail = ''): void
{
    global $failures, $checks;
    $checks++;
    if (!$held) {
        $failures[] = "$label" . ($detail !== '' ? ": $detail" : '');
        echo "FAIL $label" . ($detail !== '' ? ": $detail" : '') . "\n";
    } else {
        echo "ok   $label\n";
    }
}

function expectException(string $label, string $pattern, callable $body): void
{
    try {
        $body();
    } catch (Throwable $error) {
        check($label, (bool) preg_match($pattern, $error->getMessage()), $error->getMessage());
        return;
    }
    check($label, false, 'no exception was raised');
}

// -- 1. the inline declarations match rci.h ---------------------------------

$header = getenv('RCI_HEADER') ?: __DIR__ . '/../rci.h';
if (is_file($header)) {
    preg_match_all('/(rci_[a-z0-9_]+)\(/', file_get_contents($header), $names);
    $headerFunctions = array_values(array_unique($names[1]));
    preg_match_all('/(rci_[a-z0-9_]+)\(/', file_get_contents(__DIR__ . '/rci.php'), $inline);
    $inlineFunctions = array_values(array_unique($inline[1]));
    $missing = array_diff($headerFunctions, $inlineFunctions);
    check('rci.php declares every function rci.h declares', $missing === [], implode(', ', $missing));
    check('rci.h exposes 17 functions', count($headerFunctions) === 17, (string) count($headerFunctions));
} else {
    check('rci.h is available to compare against', false, $header);
}

// -- 2. the surface ---------------------------------------------------------

$rci = new Rci();
check('the ABI reports version 2 or newer', $rci->abiVersion >= 2, (string) $rci->abiVersion);

$targets = $rci->targets();
check('48 presets', count($targets) === 48, (string) count($targets));
$profiles = $rci->profiles();
check('more profiles than presets', count($profiles) > count($targets), (string) count($profiles));
check('every preset is selectable', array_diff($targets, $profiles) === []);

$info = $rci->profileInfo('chrome150');
check('profile family', ($info['family'] ?? '') === 'chrome', (string) ($info['family'] ?? ''));
check('chrome150 has http3', ($info['has_http3'] ?? false) === true);
expectException('unknown profile is an error', '/unknown profile/', function () use ($rci) {
    $rci->profileInfo('definitely-not-a-profile');
});

// -- 3. requests ------------------------------------------------------------

$client = $rci->client('chrome150');
$reply = $client->get("$base/index.html");
check('GET status 200', $reply->status === 200, (string) $reply->status);
check('GET body is text', $reply->bodyIsText === true);
check('GET body content', $reply->text() === 'hello from rust-curl-impersonate', $reply->text());
check('GET reports a version', in_array($reply->version, ['HTTP/1.1', 'HTTP/2.0'], true), $reply->version);
check('header lookup is case-insensitive', str_contains((string) $reply->header('CONTENT-TYPE'), 'text/plain'));

$binary = $rci->get('chrome150', "$base/rci-smoke.bin");
check('non-utf8 body is not text', $binary->bodyIsText === false);
check('hex decodes back', $binary->content() === "\x00\x01\x02\xff\xfe binary", bin2hex($binary->content()));

$echo = $client->requestWithHeaders('POST', "$base/echo", [['x-marker', 'php']], '{"a":1}');
$reflected = json_decode($echo->text(), true);
check('per-request header arrived', ($reflected['headers']['x-marker'] ?? '') === 'php');
check('POST body arrived', ($reflected['body'] ?? '') === '{"a":1}');

expectException('an unknown option is refused', '/unknown option/', function () use ($rci) {
    $rci->client('chrome150', ['timeoutms' => 1000]);
});
$typed = $rci->client('chrome150', [
    'timeout_ms' => 5000,
    'headers' => [['accept-language', 'zh-CN']],
]);
$typed->close();
check('a known option is accepted', true);

// -- 4. redirect policy -----------------------------------------------------

$redirect = $rci->get('chrome150', "$base/redirect");
check('a redirect comes back as 302', $redirect->status === 302, (string) $redirect->status);
check('Location is present', $redirect->header('Location') !== null, (string) $redirect->header('Location'));

expectException('follow_safe refuses a loopback hop', '/blocked/', function () use ($rci, $base) {
    $client = $rci->client('chrome150', ['follow_safe' => true]);
    try {
        $client->get("$base/redirect");
    } finally {
        $client->close();
    }
});

// -- 5. state on the handle -------------------------------------------------

$persistent = $rci->client('chrome150');
$persistent->get("$base/cookie");
$cookieEcho = json_decode($persistent->get("$base/echo")->text(), true);
check('the cookie jar carried to the next request', str_contains((string) ($cookieEcho['headers']['cookie'] ?? ''), 'sid=abc123'), (string) ($cookieEcho['headers']['cookie'] ?? ''));
$activity = $persistent->activity();
check('the cookie change is recorded', count($activity['cookies'] ?? []) >= 1, json_encode($activity));
$persistent->close();

check('wire profile', $client->wireProfile() === 'chrome150', $client->wireProfile());
$client->get("$base/index.html");
check('last headers are introspectable', count($client->lastHeaders()) > 0);
$client->close();
expectException('a closed client refuses requests', '/closed/', function () use ($client, $base) {
    $client->get("$base/index.html");
});

// -- 6. runtime registration ------------------------------------------------

$rci->loadFingerprints('[{"name":"php_test_client","extends":"chrome150","family":"chrome","platform":"linux"}]');
check('a registered record resolves', ($rci->profileInfo('php_test_client')['wire'] ?? '') === 'chrome150');
expectException('an unbuildable record is rejected', '/NO_CIPHER_MATCH/', function () use ($rci) {
    $rci->loadFingerprints('[{"name":"php_bad","tls":{"ciphers":"NOT_A_CIPHER"}}]');
});

// -- 7. optional network check ---------------------------------------------

if (getenv('PHP_NETWORK')) {
    $http1 = $rci->client('chrome150', ['http1_only' => true]);
    $public = $http1->get('https://example.com/');
    check('http1_only forces HTTP/1.1', $public->version === 'HTTP/1.1', $public->version);
    $http1->close();
} else {
    echo "skip http1_only over the public internet (set PHP_NETWORK=1 to include it)\n";
}

// -- summary ----------------------------------------------------------------

echo "\n", $checks - count($failures), '/', $checks, " checks passed\n";
exit($failures === [] ? 0 : 1);
