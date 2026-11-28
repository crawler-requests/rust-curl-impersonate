<?php
/**
 * rust-curl-impersonate C ABI (ABI v2) binding for PHP 7.4+ FFI.
 *
 *     require 'rci.php';
 *     $rci = new Rci('/path/to/librust_curl_impersonate_ffi.so');
 *     $client = $rci->client('chrome150');
 *     $reply = $client->get('https://tls.peet.ws/api/all');
 *     echo $reply->status, ' ', $reply->version, "\n";
 *     $client->close();
 *
 * PHP's FFI::cdef cannot parse the comments and #include lines in rci.h, so the
 * declarations below are an inline copy of the 17 prototypes. They are asserted
 * against rci.h's function names by the binding's test suite, which is the
 * point: PHP is the one language where the declarations are hand-held.
 */

const RCI_ABI_VERSION = 2;

class RciError extends RuntimeException {}

/** One request's result, in the ABI's JSON shape. */
class RciResponse
{
    public $status;
    public $version;
    public $url;
    /** @var array<int, array{0:string,1:string}> */
    public $headers;
    public $body;
    public $bodyIsText;

    public function __construct(array $reply)
    {
        $this->status = $reply['status'] ?? 0;
        $this->version = $reply['version'] ?? 'unknown';
        $this->url = $reply['url'] ?? '';
        $this->headers = $reply['headers'] ?? [];
        $this->body = $reply['body'] ?? '';
        $this->bodyIsText = $reply['body_is_text'] ?? true;
    }

    /** First value for a header name, case-insensitively. */
    public function header(string $name): ?string
    {
        foreach ($this->headers as $pair) {
            if (strcasecmp($pair[0], $name) === 0) {
                return $pair[1];
            }
        }
        return null;
    }

    /**
     * The body as bytes. The ABI sends anything that is not valid UTF-8 as
     * lowercase hex, so this decodes it; text passes through.
     */
    public function content(): string
    {
        if ($this->bodyIsText) {
            return $this->body;
        }
        $decoded = @hex2bin($this->body);
        if ($decoded === false) {
            throw new RciError('binary body is not valid hex');
        }
        return $decoded;
    }

    public function text(): string
    {
        if (!$this->bodyIsText) {
            throw new RciError('body is binary; call content()');
        }
        return $this->body;
    }
}

class RciClient
{
    /** @var Rci */
    private $rci;
    private $handle;
    public $profile;
    private $closed = false;

    public function __construct(Rci $rci, $handle, string $profile)
    {
        $this->rci = $rci;
        $this->handle = $handle;
        $this->profile = $profile;
    }

    private function check(): void
    {
        if ($this->closed || $this->handle === null) {
            throw new RciError('rci: client is closed');
        }
    }

    /** Send a request with a byte body. */
    public function request(string $method, string $url, ?string $body = null): RciResponse
    {
        $this->check();
        $pointer = $this->rci->ffi->rci_request(
            $this->handle,
            $method,
            $url,
            $body,                              // null means "no body"
            $body === null ? 0 : strlen($body)
        );
        return $this->rci->response($pointer, 'request');
    }

    /**
     * The ABI's per-request-header path. Its body is NUL-terminated, so it
     * cannot carry binary data; `request` is the one for that.
     */
    public function requestWithHeaders(string $method, string $url, array $headers = [], ?string $body = null): RciResponse
    {
        $this->check();
        $pointer = $this->rci->ffi->rci_request_with(
            $this->handle,
            $method,
            $url,
            $headers === [] ? null : json_encode($headers),
            $body
        );
        return $this->rci->response($pointer, 'request_with');
    }

    public function get(string $url): RciResponse
    {
        return $this->request('GET', $url);
    }

    public function post(string $url, string $body): RciResponse
    {
        return $this->requestWithHeaders('POST', $url, [], $body);
    }

    public function lastHeaders(): array
    {
        $this->check();
        return $this->rci->json($this->rci->ffi->rci_client_last_headers($this->handle), 'last_headers');
    }

    public function activity(): array
    {
        $this->check();
        return $this->rci->json($this->rci->ffi->rci_client_activity($this->handle), 'activity');
    }

    public function wireProfile(): string
    {
        $this->check();
        return $this->rci->text($this->rci->ffi->rci_client_profile($this->handle));
    }

    public function close(): void
    {
        if ($this->closed) {
            return;
        }
        $this->rci->ffi->rci_client_free($this->handle);
        $this->closed = true;
        $this->handle = null;
    }

    public function __destruct()
    {
        $this->close();
    }
}

class Rci
{
    /** @var FFI */
    public $ffi;
    public $libraryPath;
    public $abiVersion;

    public function __construct(?string $path = null)
    {
        $this->libraryPath = self::resolveLibrary($path);
        // An inline copy of rci.h: FFI::cdef cannot read the header's comments
        // and #include lines. The function names and parameter types are
        // identical; the binding's tests compare the two.
        $this->ffi = FFI::cdef(<<<'C'
typedef struct RciClient RciClient;
typedef unsigned int uint32_t;
typedef unsigned long size_t;
typedef unsigned char uint8_t;

uint32_t rci_version(void);
char *rci_targets(void);
char *rci_profiles(void);
char *rci_profile_info(const char *profile);
RciClient *rci_client_new(const char *profile);
RciClient *rci_client_new_with_options(const char *profile, const char *options_json);
void rci_client_free(RciClient *handle);
char *rci_client_profile(RciClient *handle);
char *rci_request(RciClient *handle, const char *method, const char *url, const uint8_t *body, size_t body_len);
char *rci_request_with(RciClient *handle, const char *method, const char *url, const char *headers_json, const char *body);
char *rci_get(const char *profile, const char *url);
char *rci_http3_get(const char *profile, const char *addr, const char *host, const char *path);
char *rci_client_last_headers(RciClient *handle);
char *rci_client_activity(RciClient *handle);
const char *rci_last_error(void);
char *rci_load_fingerprints(const char *json);
void rci_string_free(char *text);
C, $this->libraryPath);

        $this->abiVersion = $this->ffi->rci_version();
        if ($this->abiVersion < RCI_ABI_VERSION) {
            throw new RciError(sprintf(
                'library at %s reports ABI %d, this binding needs >= %d',
                $this->libraryPath,
                $this->abiVersion,
                RCI_ABI_VERSION
            ));
        }
    }

    public static function libraryName(): string
    {
        if (PHP_OS_FAMILY === 'Darwin') {
            return 'librust_curl_impersonate_ffi.dylib';
        }
        if (PHP_OS_FAMILY === 'Windows') {
            return 'rust_curl_impersonate_ffi.dll';
        }
        return 'librust_curl_impersonate_ffi.so';
    }

    /** Candidate locations, covering the archive layout and a cargo build. */
    public static function candidateDirs(): array
    {
        $here = __DIR__;
        return array_values(array_filter([
            getenv('RCI_LIB_DIR') ?: null,
            $here . '/lib',
            $here . '/../lib',
            $here . '/../../../target/release',
            getcwd() . '/lib',
        ]));
    }

    public static function resolveLibrary(?string $explicit = null): string
    {
        $name = self::libraryName();
        $explicit = $explicit ?: (getenv('RCI_LIB') ?: null);
        if ($explicit !== null) {
            if (is_dir($explicit)) {
                $explicit .= '/' . $name;
            }
            if (!is_file($explicit)) {
                throw new RciError("no shared library at $explicit");
            }
            return $explicit;
        }
        foreach (self::candidateDirs() as $dir) {
            $candidate = $dir . '/' . $name;
            if (is_file($candidate)) {
                return $candidate;
            }
        }
        throw new RciError(sprintf(
            '%s not found; set RCI_LIB or RCI_LIB_DIR (looked in %s)',
            $name,
            implode(', ', self::candidateDirs())
        ));
    }

    /**
     * Read a library-owned string and free it. Every `char *` the ABI returns
     * is released this way; `rci_last_error` is borrowed and never freed.
     */
    public function text($pointer): string
    {
        if ($pointer === null) {
            return '';
        }
        $text = FFI::string($pointer);
        $this->ffi->rci_string_free($pointer);
        return $text;
    }

    public function json($pointer, string $label): array
    {
        $text = $this->text($pointer);
        $value = json_decode($text, true);
        if (!is_array($value)) {
            throw new RciError("$label: library returned non-JSON (" . substr($text, 0, 120) . ')');
        }
        if (isset($value['error']) && is_string($value['error'])) {
            throw new RciError($value['error']);
        }
        return $value;
    }

    public function response($pointer, string $label): RciResponse
    {
        return new RciResponse($this->json($pointer, $label));
    }

    public function targets(): array
    {
        return $this->json($this->ffi->rci_targets(), 'targets');
    }

    public function profiles(): array
    {
        return $this->json($this->ffi->rci_profiles(), 'profiles');
    }

    public function profileInfo(string $name): array
    {
        return $this->json($this->ffi->rci_profile_info($name), 'profile_info');
    }

    public function lastError(): string
    {
        return (string) $this->ffi->rci_last_error();
    }

    /**
     * Create a handle. Unknown option keys are refused here, with the list of
     * keys the ABI accepts, so a typo does not become a silently ignored
     * setting; the library would refuse the same document.
     */
    public function client(string $profile, array $options = []): RciClient
    {
        $encoded = self::encodeOptions($options);
        $handle = $encoded === null
            ? $this->ffi->rci_client_new($profile)
            : $this->ffi->rci_client_new_with_options($profile, $encoded);
        if ($handle === null) {
            $message = $this->lastError();
            throw new RciError($message !== '' ? $message : 'rci_client_new returned NULL');
        }
        return new RciClient($this, $handle, $profile);
    }

    public function get(string $profile, string $url): RciResponse
    {
        return $this->response($this->ffi->rci_get($profile, $url), 'get');
    }

    public function http3Get(string $profile, string $addr, string $host, string $path): RciResponse
    {
        return $this->response($this->ffi->rci_http3_get($profile, $addr, $host, $path), 'http3_get');
    }

    /**
     * Register a library-schema JSON document for this process. The whole
     * document is validated before anything is kept, so success means the
     * records can be sent.
     */
    public function loadFingerprints(string $document): void
    {
        $this->json($this->ffi->rci_load_fingerprints($document), 'load_fingerprints');
    }

    private const OPTION_KEYS = [
        'timeout_ms' => 'timeout_ms',
        'proxy' => 'proxy',
        'follow_redirects' => 'follow_redirects',
        'follow_safe' => 'follow_safe',
        'pool_max_idle_per_host' => 'pool_max_idle_per_host',
        'headers' => 'headers',
        'split_cookies' => 'split_cookies',
        'http1_only' => 'http1_only',
    ];

    public static function encodeOptions(array $options): ?string
    {
        if ($options === []) {
            return null;
        }
        $unknown = array_diff(array_keys($options), array_keys(self::OPTION_KEYS));
        if ($unknown !== []) {
            throw new RciError('unknown option ' . implode(', ', $unknown)
                . '; the ABI accepts ' . implode(', ', array_keys(self::OPTION_KEYS)));
        }
        return json_encode($options);
    }
}
