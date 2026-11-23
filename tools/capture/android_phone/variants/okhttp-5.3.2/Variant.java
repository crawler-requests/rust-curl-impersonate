package io.capture.phone;

import java.net.Proxy;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/** OkHttp 5.3.2, linked directly so the captured hello is certainly its. */
final class Variant {
    private Variant() {
    }

    static void request(String kind, String url, Proxy proxy) throws Exception {
        if (!"okhttp".equals(kind)) {
            throw new UnsupportedOperationException("this build links OkHttp only");
        }
        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(6, java.util.concurrent.TimeUnit.SECONDS)
                .readTimeout(6, java.util.concurrent.TimeUnit.SECONDS)
                .retryOnConnectionFailure(false);
        if (proxy != null) {
            builder.proxy(proxy);
        }
        // OkHttp's default ALPN comes from its protocols list; set it
        // explicitly so a hello always carries http/1.1 (and h2 on 4+),
        // which is what every real OkHttp hello does.
        try {
            builder.protocols(java.util.Arrays.asList(
                    okhttp3.Protocol.HTTP_2, okhttp3.Protocol.HTTP_1_1));
        } catch (Throwable olderOkHttpHasNoProtocolBuilderMethod) {
            // OkHttp 3.0 predates the builder method; its hello is captured
            // uncapped only.
        }
        // A TLS 1.2-only OkHttp is how Android 8/9 talk: keep OkHttp's own
        // cipher list and disable the TLS 1.3 protocol, which removes the
        // TLS 1.3 suites and supported_versions from the hello.
        if ("1.2".equals(io.capture.phone.Stacks.maxVersion)) {
            // Wrap the factory OkHttp built for itself, so its ALPN callback
            // survives; only the protocol list is narrowed.
            // OkHttp installs its ALPN and session-ticket behaviour through
            // the factory it built, so this wraps that one rather than the
            // platform's; replacing it would drop both extensions.
            OkHttpClient assembled = builder.build();
            builder.sslSocketFactory(
                    io.capture.phone.CappedSocketFactory
                            .wrappingOkHttpAlpn(assembled, "TLSv1.2"),
                    io.capture.phone.CappedSocketFactory.permissive());
        }
        Request request = new Request.Builder().url(url).build();
        try (Response response = builder.build()
                .newCall(request).execute()) {
            // The echo path returns tls.peet.ws's own report; logging the
            // body is what makes that server-side check available.
            String body = response.body() == null ? "" : response.body().string();
            android.util.Log.i(Main.TAG, "okhttp status " + response.code()
                    + " body " + body.substring(0, Math.min(body.length(), 6000)));
        }
    }
}
