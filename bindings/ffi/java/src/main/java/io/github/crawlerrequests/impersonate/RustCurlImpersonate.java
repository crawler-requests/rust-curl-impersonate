package io.github.crawlerrequests.impersonate;

import com.sun.jna.Pointer;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The typed facade over {@link RciLibrary}: the entry point every Java caller
 * uses.
 *
 * <pre>
 * try (RustCurlImpersonate.Client client = RustCurlImpersonate.client("chrome150")) {
 *     RustCurlImpersonate.Response reply = client.get("https://tls.peet.ws/api/all");
 *     System.out.println(reply.status() + " " + reply.version());
 * }
 * </pre>
 *
 * Every method is a synchronous native call. One {@code Client} per thread: the
 * handle owns a runtime and is not thread-safe.
 */
public final class RustCurlImpersonate {

    private RustCurlImpersonate() {}

    // -- library-wide queries ---------------------------------------------------

    public static int abiVersion() {
        return RciNative.library().rci_version();
    }

    /** The 48 curl-impersonate preset names. */
    public static List<String> targets() {
        return strings(RciNative.library().rci_targets());
    }

    /** Every selectable name: the presets plus the fingerprint library's records. */
    public static List<String> profiles() {
        return strings(RciNative.library().rci_profiles());
    }

    /** Metadata for one profile name; unknown names raise {@link RciException}. */
    public static Profile profileInfo(String name) {
        Map<String, Object> info = object(RciNative.library().rci_profile_info(name));
        if (info.containsKey("error")) {
            throw new RciException(String.valueOf(info.get("error")));
        }
        return new Profile(name, info);
    }

    /** Register a library-schema JSON document for this process. */
    public static void loadFingerprints(String json) {
        Map<String, Object> reply = object(RciNative.library().rci_load_fingerprints(json));
        if (reply.containsKey("error")) {
            throw new RciException(String.valueOf(reply.get("error")));
        }
    }

    /** Register one record as a one-record library document. */
    public static void loadFingerprints(Map<String, Object> record) {
        loadFingerprints(RciJsonWriter.wrap(record));
    }

    // -- clients ----------------------------------------------------------------

    /** A client on the profile's default settings (30 s timeout). */
    public static Client client(String profile) {
        return new Client(profile, null);
    }

    /** A client with options JSON (see {@code rci.h}}, NULL for defaults). */
    public static Client client(String profile, String optionsJson) {
        return new Client(profile, optionsJson);
    }

    /** A client from typed settings; unknown fields raise {@link RciException}. */
    public static Client client(String profile, Settings settings) {
        return new Client(profile, settings.toJson());
    }

    /** One-shot GET: builds a client, sends the request, frees the client. */
    public static Response get(String profile, String url) {
        Map<String, Object> reply = object(RciNative.library().rci_get(profile, url));
        return new Response(reply);
    }

    /** GET over HTTP/3. {@code addr} is "ip:port" or a resolvable host. */
    public static Response http3Get(String profile, String addr, String host, String path) {
        Map<String, Object> reply = object(
                RciNative.library().rci_http3_get(profile, addr, host, path));
        return new Response(reply);
    }

    // -- helpers ------------------------------------------------------------------

    static List<String> strings(Pointer pointer) {
        Object parsed = RciJson.parse(RciNative.peek(pointer));
        // Read before freeing: the pointer is the library's allocation.
        RciNative.freeIfAny(pointer);
        List<String> names = new ArrayList<>();
        if (parsed instanceof List) {
            for (Object item : (List<?>) parsed) {
                names.add(String.valueOf(item));
            }
        }
        return names;
    }

    static Map<String, Object> object(Pointer pointer) {
        String text = RciNative.peek(pointer);
        RciNative.freeIfAny(pointer);
        if (text == null) {
            throw new IllegalStateException("library returned a null string");
        }
        return RciJson.parseObject(text);
    }

    // -- nested types ---------------------------------------------------------------

    /** One profile's metadata, with accessors for each documented field. */
    public static final class Profile {
        private final String name;
        private final Map<String, Object> info;

        Profile(String name, Map<String, Object> info) {
            this.name = name;
            this.info = info;
        }

        public String name() { return name; }
        public String wire() { return string("wire"); }
        public String family() { return string("family"); }
        public String platform() { return string("platform"); }
        public String fidelity() { return string("fidelity"); }
        public String deviation() { return string("deviation"); }
        public String source() { return string("source"); }
        public boolean http1Only() { return Boolean.TRUE.equals(info.get("http1_only")); }
        public boolean hasHttp3() { return Boolean.TRUE.equals(info.get("has_http3")); }

        /** The raw JSON object, including fields added by a later ABI. */
        public Map<String, Object> raw() { return new LinkedHashMap<>(info); }

        private String string(String key) {
            Object value = info.get(key);
            return value == null ? null : String.valueOf(value);
        }

        @Override
        public String toString() {
            return "Profile(" + name + ", family=" + family() + ")";
        }
    }

    /** Typed form of {@code rci_client_new_with_options}' JSON object. */
    public static final class Settings {
        Long timeoutMs;
        String proxy;
        Boolean followRedirects;
        Boolean followSafe;
        Integer poolMaxIdlePerHost;
        List<String[]> headers = new ArrayList<>();
        Boolean splitCookies;
        Boolean http1Only;

        public Settings timeoutMs(long value) { this.timeoutMs = value; return this; }
        public Settings proxy(String value) { this.proxy = value; return this; }
        public Settings followRedirects(boolean value) { this.followRedirects = value; return this; }
        public Settings followSafe(boolean value) { this.followSafe = value; return this; }
        public Settings poolMaxIdlePerHost(int value) { this.poolMaxIdlePerHost = value; return this; }
        public Settings header(String name, String value) {
            this.headers.add(new String[] {name, value});
            return this;
        }
        public Settings splitCookies(boolean value) { this.splitCookies = value; return this; }
        public Settings http1Only(boolean value) { this.http1Only = value; return this; }

        String toJson() {
            List<String> fields = new ArrayList<>();
            if (timeoutMs != null) fields.add("\"timeout_ms\":" + timeoutMs);
            if (proxy != null) fields.add("\"proxy\":" + RciJsonWriter.quote(proxy));
            if (followRedirects != null) fields.add("\"follow_redirects\":" + followRedirects);
            if (followSafe != null) fields.add("\"follow_safe\":" + followSafe);
            if (poolMaxIdlePerHost != null) fields.add("\"pool_max_idle_per_host\":" + poolMaxIdlePerHost);
            if (!headers.isEmpty()) {
                List<String> pairs = new ArrayList<>();
                for (String[] pair : headers) {
                    pairs.add("[" + RciJsonWriter.quote(pair[0]) + "," + RciJsonWriter.quote(pair[1]) + "]");
                }
                fields.add("\"headers\":[" + String.join(",", pairs) + "]");
            }
            if (splitCookies != null) fields.add("\"split_cookies\":" + splitCookies);
            if (http1Only != null) fields.add("\"http1_only\":" + http1Only);
            return "{" + String.join(",", fields) + "}";
        }
    }

    /** One profile's handle. Close it, or use it in try-with-resources. */
    public static final class Client implements AutoCloseable {
        private final RciLibrary library;
        private final String profile;
        private Pointer handle;

        Client(String profile, String optionsJson) {
            this.library = RciNative.library();
            this.profile = profile;
            this.handle = library.rci_client_new_with_options(profile, optionsJson);
            if (this.handle == null) {
                throw new RciException(RciNative.lastError());
            }
        }

        /** Send one request with a string body (NUL-terminated, UTF-8). */
        public Response send(String method, String url, String body) {
            return send(method, url, body, (String) null);
        }

        /** Send one request with per-request headers JSON ({@code [["n","v"],...]}). */
        public Response send(String method, String url, String body, String headersJson) {
            ensureOpen();
            Map<String, Object> reply = RustCurlImpersonate.object(
                    library.rci_request_with(handle, method, url, headersJson, body));
            return new Response(reply);
        }

        /** Send one request with a byte body, no per-request headers. */
        public Response sendBytes(String method, String url, byte[] body) {
            ensureOpen();
            Map<String, Object> reply = RustCurlImpersonate.object(
                    library.rci_request(handle, method, url, body,
                            body == null ? 0 : body.length));
            return new Response(reply);
        }

        public Response get(String url) {
            return send("GET", url, null, null);
        }

        public Response post(String url, String body) {
            return send("POST", url, body, null);
        }

        /** Headers of the most recent response as name/value pairs. */
        public List<String[]> lastHeaders() {
            ensureOpen();
            Pointer pointer = library.rci_client_last_headers(handle);
            String text = RciNative.peek(pointer);
            RciNative.freeIfAny(pointer);
            Object parsed = RciJson.parse(text);
            List<String[]> pairs = new ArrayList<>();
            if (parsed instanceof List) {
                for (Object item : (List<?>) parsed) {
                    List<?> pair = (List<?>) item;
                    pairs.add(new String[] {
                            String.valueOf(pair.get(0)), String.valueOf(pair.get(1))
                    });
                }
            }
            return pairs;
        }

        /** The preset whose bytes this handle sends. */
        public String wireProfile() {
            ensureOpen();
            Pointer pointer = library.rci_client_profile(handle);
            String text = RciNative.peek(pointer);
            RciNative.freeIfAny(pointer);
            return text;
        }

        /**
         * Cookie changes and redirect history recorded by this handle:
         * {@code {"cookies":[...], "redirects":[...]}}.
         */
        public Map<String, Object> activity() {
            ensureOpen();
            return RustCurlImpersonate.object(library.rci_client_activity(handle));
        }

        @Override
        public void close() {
            if (handle != null) {
                library.rci_client_free(handle);
                handle = null;
            }
        }

        private void ensureOpen() {
            if (handle == null) {
                throw new IllegalStateException("client is closed");
            }
        }
    }

    /** A response JSON object. {@code content()} decodes the hex form of a binary body. */
    public static final class Response {
        private final Map<String, Object> reply;

        Response(Map<String, Object> reply) {
            if (reply.containsKey("error")) {
                throw new RciException(String.valueOf(reply.get("error")));
            }
            this.reply = reply;
        }

        public int status() { return ((Number) reply.get("status")).intValue(); }
        public boolean ok() { int s = status(); return s >= 200 && s < 300; }
        public String version() { return (String) reply.get("version"); }
        public String url() { return (String) reply.get("url"); }
        public boolean bodyIsText() { return Boolean.TRUE.equals(reply.get("body_is_text")); }
        public String bodyText() { return (String) reply.get("body"); }

        /** The body as bytes; a binary body arrives as lowercase hex and is decoded. */
        public byte[] content() {
            String body = (String) reply.get("body");
            if (bodyIsText()) {
                return body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
            }
            return hexToBytes(body);
        }

        public List<String[]> headers() {
            List<String[]> pairs = new ArrayList<>();
            Object raw = reply.get("headers");
            if (raw instanceof List) {
                for (Object item : (List<?>) raw) {
                    List<?> pair = (List<?>) item;
                    pairs.add(new String[] {
                            String.valueOf(pair.get(0)), String.valueOf(pair.get(1))
                    });
                }
            }
            return pairs;
        }

        /** First value of a header (case-insensitive), or null. */
        public String header(String name) {
            for (String[] pair : headers()) {
                if (pair[0].equalsIgnoreCase(name)) {
                    return pair[1];
                }
            }
            return null;
        }

        public Map<String, Object> raw() { return new LinkedHashMap<>(reply); }

        private static byte[] hexToBytes(String hex) {
            if (hex == null) {
                return new byte[0];
            }
            int length = hex.length() / 2;
            byte[] bytes = new byte[length];
            for (int i = 0; i < length; i++) {
                bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
            }
            return bytes;
        }
    }
}
