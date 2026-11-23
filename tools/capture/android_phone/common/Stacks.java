package io.capture.phone;

import android.util.Log;

import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;

/**
 * One request through one stack. The library half lives in the variant's
 * {@link Variant}, so a build links exactly one library version and the
 * ClientHello on the wire is provably that client's.
 *
 * Every stack is expected to fail: the listener never answers the handshake.
 * What matters is that the ClientHello went out, so the error is logged and
 * never retried.
 */
final class Stacks {
    private static final String TAG = "PhoneCap";

    private Stacks() {
    }

    /** Cap the platform stack's TLS version, e.g. "1.2"; empty means default. */
    static String maxVersion = "";

    static void run(String label, String kind, String url, String proxyValue)
            throws Exception {
        Log.i(TAG, "begin " + label + " " + url);
        try {
            Proxy proxy = parseProxy(proxyValue);
            if ("urlconn".equals(kind)) {
                urlConn(url, proxy);
            } else if ("webview".equals(kind)) {
                // Handled on the UI thread by RunStacks.
            } else {
                Variant.request(kind, url, proxy);
            }
        } catch (Throwable error) {
            // The stack trace is what says why a library version did not
            // start; the exception's toString alone hides the cause.
            Log.i(TAG, label + " failed: " + Log.getStackTraceString(error));
        }
        Log.i(TAG, "end " + label);
    }

    static Proxy parseProxy(String value) {
        if (value == null || value.length() == 0) {
            return null;
        }
        String[] parts = value.split(":");
        return new Proxy(Proxy.Type.HTTP,
                InetSocketAddress.createUnresolved(parts[0],
                        Integer.parseInt(parts[1])));
    }

    /** HttpsURLConnection as the app sees it: the platform Conscrypt. */
    private static void urlConn(String url, Proxy proxy) throws Exception {
        URL target = new URL(url);
        URLConnection connection = proxy == null
                ? target.openConnection()
                : target.openConnection(proxy);
        // A TLS 1.2-only client is how older Android releases talk; capping
        // the platform stack reproduces that without an older image.
        if (connection instanceof javax.net.ssl.HttpsURLConnection
                && maxVersion.length() > 0) {
            javax.net.ssl.HttpsURLConnection https =
                    (javax.net.ssl.HttpsURLConnection) connection;
            String protocol = "1.3".equals(maxVersion) ? "TLSv1.3" : "TLSv1.2";
            https.setSSLSocketFactory(CappedSocketFactory.of(https, protocol));
        }
        connection.setConnectTimeout(60000);
        connection.setReadTimeout(60000);
        if (CappedSocketFactory.includeSct
                && connection instanceof javax.net.ssl.HttpsURLConnection) {
            javax.net.ssl.HttpsURLConnection https =
                    (javax.net.ssl.HttpsURLConnection) connection;
            https.setSSLSocketFactory(
                    new CappedSocketFactory(https.getSSLSocketFactory())
                            .withSct());
        }
        try (InputStream in = connection.getInputStream()) {
            byte[] buffer = new byte[8192];
            while (in.read(buffer) > 0) {
                // Reading keeps the socket up long enough for the ClientHello
                // to have gone out; the body itself is not used.
            }
        }
    }
}
