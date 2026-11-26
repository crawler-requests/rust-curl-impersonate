package io.github.crawlerrequests.impersonate;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the JNA wrapper against a locally built library and the HTTP test
 * server from {@code bindings/ffi/python/testserver.py}.
 *
 * <pre>
 * cargo build -p rust-curl-impersonate-ffi --release
 * python3 bindings/ffi/python/testserver.py 8765 &amp;
 * RCI_LIB=target/release/librust_curl_impersonate_ffi.so mvn test
 * </pre>
 */
class RustCurlImpersonateTest {

    private static String setting(String property, String environment, String fallback) {
        String value = System.getProperty(property);
        if (value == null || value.isBlank()) {
            value = System.getenv(environment);
        }
        return value == null || value.isBlank() ? fallback : value;
    }

    private static final String BASE = setting("rci.base", "RCI_BASE",
            "http://127.0.0.1:8765");

    @Test
    void abiVersionIsTwo() {
        assertEquals(2, RustCurlImpersonate.abiVersion());
    }

    @Test
    void targetsAndProfiles() {
        List<String> targets = RustCurlImpersonate.targets();
        List<String> profiles = RustCurlImpersonate.profiles();
        assertEquals(48, targets.size());
        assertTrue(profiles.containsAll(targets));
        assertTrue(profiles.size() > targets.size());
    }

    @Test
    void profileInfo() {
        RustCurlImpersonate.Profile chrome = RustCurlImpersonate.profileInfo("chrome150");
        assertEquals("chrome", chrome.family());
        assertTrue(chrome.hasHttp3());
        assertEquals("chrome150", chrome.wire());

        RustCurlImpersonate.Profile go = RustCurlImpersonate.profileInfo("go1.26");
        assertEquals("go", go.family());
        assertEquals("close", go.fidelity());
        assertFalse(go.hasHttp3());
        assertTrue(go.deviation().contains("BoringSSL"));
    }

    @Test
    void unknownProfileIsAnException() {
        assertThrows(RciException.class,
                () -> RustCurlImpersonate.profileInfo("definitely-not-a-profile"));
    }

    @Test
    void oneShotGet() {
        RustCurlImpersonate.Response reply =
                RustCurlImpersonate.get("chrome150", BASE + "/index.html");
        assertEquals(200, reply.status());
        assertTrue(reply.ok());
        assertEquals("hello from rust-curl-impersonate", reply.bodyText());
        assertTrue(reply.header("Content-Type").startsWith("text/plain"));
    }

    @Test
    void binaryBodyIsDecodedFromHex() {
        RustCurlImpersonate.Response reply =
                RustCurlImpersonate.get("chrome150", BASE + "/rci-smoke.bin");
        assertFalse(reply.bodyIsText());
        assertNotNull(reply.content());
        assertEquals(12, reply.content().length);
    }

    @Test
    void clientSendsPostWithHeaders() {
        try (RustCurlImpersonate.Client client =
                     RustCurlImpersonate.client("chrome150", new RustCurlImpersonate.Settings()
                             .header("accept-language", "zh-CN"))) {
            RustCurlImpersonate.Response reply = client.send(
                    "POST", BASE + "/echo", "{\"a\":1}", "[[\"x-test\",\"yes\"]]");
            assertEquals(200, reply.status());
            Map<String, Object> echo = RciJson.parseObject(reply.bodyText());
            assertEquals("POST", echo.get("method"));
            assertTrue(((Map<?, ?>) echo.get("headers")).get("x-test") != null);
        }
    }

    @Test
    void headersOptionBlocksDefaultHeader() {
        try (RustCurlImpersonate.Client client =
                     RustCurlImpersonate.client("chrome150", new RustCurlImpersonate.Settings()
                             .header("user-agent", ""))) {
            RustCurlImpersonate.Response reply = client.send("POST", BASE + "/echo", "x", null);
            Map<?, ?> headers = (Map<?, ?>) RciJson.parseObject(reply.bodyText()).get("headers");
            assertFalse(headers.containsKey("user-agent"));
            assertTrue(headers.containsKey("accept-language"));
        }
    }

    @Test
    void unknownOptionIsRejected() {
        assertThrows(RciException.class,
                () -> RustCurlImpersonate.client("chrome150", "{\"nonesuch\":true}"));
    }

    @Test
    void requestErrorIsAnException() {
        Executable call = () -> RustCurlImpersonate.client("chrome150", new RustCurlImpersonate.Settings()
                .timeoutMs(2000)).get("http://127.0.0.1:1/");
        assertThrows(RciException.class, call);
    }

    @Test
    void redirectNotFollowedByDefault() {
        RustCurlImpersonate.Response reply =
                RustCurlImpersonate.get("chrome150", BASE + "/redirect");
        assertEquals(302, reply.status());
        assertTrue(reply.url().endsWith("/redirect"));
    }

    @Test
    void followSafeRefusesLoopback() {
        try (RustCurlImpersonate.Client client =
                     RustCurlImpersonate.client("chrome150", new RustCurlImpersonate.Settings()
                             .followSafe(true))) {
            assertThrows(RciException.class, () -> client.get(BASE + "/redirect"));
            assertFalse(((List<?>) client.activity().get("redirects")).isEmpty());
        }
    }

    @Test
    void lastHeadersAndWireProfile() {
        try (RustCurlImpersonate.Client client = RustCurlImpersonate.client("chrome150")) {
            assertEquals("chrome150", client.wireProfile());
            assertTrue(client.lastHeaders().isEmpty());
            client.get(BASE + "/index.html");
            assertFalse(client.lastHeaders().isEmpty());
        }
    }

    @Test
    void loadFingerprintsAddsAName() {
        RustCurlImpersonate.loadFingerprints(
                "[{\"name\":\"java_test_record\",\"family\":\"test\",\"platform\":\"linux\","
                        + "\"extends\":\"chrome150\",\"source\":\"junit\"}]");
        RustCurlImpersonate.Profile record = RustCurlImpersonate.profileInfo("java_test_record");
        assertEquals("chrome150", record.wire());
        assertEquals("test", record.family());
    }

    @Test
    void http3UnavailableIsAnError() {
        assertThrows(RciException.class,
                () -> RustCurlImpersonate.http3Get("go1.26", "quic.nginx.org:443",
                        "quic.nginx.org", "/"));
    }

    @Test
    void http3AgainstAPublicPeer() {
        Assumptions.assumeTrue(System.getProperty("rci.h3") != null,
                "needs outbound UDP; pass -Drci.h3=1");
        // quic.nginx.org rate-limits and closes streams intermittently.
        for (int attempt = 0; attempt < 6; attempt++) {
            try {
                RustCurlImpersonate.Response reply = RustCurlImpersonate.http3Get(
                        "chrome152", "quic.nginx.org:443", "quic.nginx.org", "/");
                assertEquals(200, reply.status());
                assertEquals("h3", reply.header("x-quic"));
                return;
            } catch (RciException error) {
                // try again
            }
        }
        Assumptions.abort("no successful HTTP/3 exchange from this network");
    }
}
