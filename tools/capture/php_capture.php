<?php
// Capture the PHP stream wrapper or the curl extension fingerprint.
$url = "https://tls.peet.ws/api/all";
$mode = $argv[1];
$out = $argv[2];

if ($mode === "streams") {
    $body = file_get_contents($url);
    if ($body === false) {
        fwrite(STDERR, "php streams: request failed\n");
        exit(1);
    }
    file_put_contents($out, $body);
    echo "php streams: ", strlen($body), "\n";
} elseif ($mode === "curl") {
    $handle = curl_init($url);
    curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
    $body = curl_exec($handle);
    if ($body === false) {
        fwrite(STDERR, "php curl: ", curl_error($handle), "\n");
        exit(1);
    }
    file_put_contents($out, $body);
    echo "php curl: ", strlen($body), " http_version=", curl_getinfo($handle, CURLINFO_HTTP_VERSION), "\n";
    curl_close($handle);
} else {
    fwrite(STDERR, "usage: php_capture.php streams|curl <output>\n");
    exit(2);
}
