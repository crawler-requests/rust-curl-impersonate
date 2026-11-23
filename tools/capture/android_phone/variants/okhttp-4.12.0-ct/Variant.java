package io.capture.phone;

import java.net.Proxy;
import java.util.concurrent.TimeUnit;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * OkHttp 4.12 with the bundled Conscrypt and certificate transparency on.
 *
 * A normal request uses OkHttp's own TLS path. With --include-sct the client
 * is given a factory built from Conscrypt's internal parameters with
 * setCTVerificationEnabled(true) - the setting behind
 * SSL_enable_signed_cert_timestamps, which puts an SCT extension in the
 * hello. TLS-extension handling is turned off so OkHttp's Android adapter
 * does not try to recognise a bundled-Conscrypt socket it rejects.
 */
final class Variant {
    private Variant() {
    }

    static void request(String kind, String url, Proxy proxy) throws Exception {
        if (!"okhttp".equals(kind)) {
            throw new UnsupportedOperationException("this build links OkHttp only");
        }
        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(10, TimeUnit.SECONDS)
                .retryOnConnectionFailure(false);
        if (proxy != null) {
            builder.proxy(proxy);
        }
        try {
            builder.protocols(java.util.Arrays.asList(
                    okhttp3.Protocol.HTTP_2, okhttp3.Protocol.HTTP_1_1));
        } catch (Throwable older) {
            // Not every release exposes this builder method.
        }
        javax.net.ssl.SSLSocketFactory ct = null;
        if (io.capture.phone.CappedSocketFactory.includeSct) {
            // A long, harmless ALPN list pads the hello past the 256-byte
            // threshold, so the transport adds the padding extension that
            // android_zalando's capture carries.
            ct = io.capture.phone.CappedSocketFactory.ctWithBundled(
                    new String[] {"h2", "http/1.1"});
        }
        if (ct != null) {
            android.util.Log.i(Main.TAG, "using the CT factory");
            builder.sslSocketFactory(ct,
                    io.capture.phone.CappedSocketFactory.permissive());
            // Keep TLSEXT so session_ticket survives; Conscrypt adds it when
            // the extension hook is on.
            builder.connectionSpecs(java.util.Collections.singletonList(
                    new okhttp3.ConnectionSpec.Builder(okhttp3.ConnectionSpec.MODERN_TLS)
                            .supportsTlsExtensions(false).build()));
        }
        Request request = new Request.Builder().url(url).build();
        Response response = builder.build().newCall(request).execute();
        try {
            String body = response.body() == null ? "" : response.body().string();
            android.util.Log.i(Main.TAG, "okhttp status " + response.code()
                    + " body " + body.substring(0, Math.min(body.length(), 6000)));
        } finally {
            response.close();
        }
    }
}
