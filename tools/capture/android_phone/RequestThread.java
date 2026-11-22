package io.capture.phone;

import android.util.Log;

import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

/**
 * One HTTPS request through one stack.
 *
 * The listener does not complete the handshake, so every request is expected
 * to throw - what matters is that the ClientHello went out first, which it
 * always does. The failure is logged, not retried.
 */
public final class RequestThread implements Runnable {
    private final String label;
    private final String url;
    private final String proxyHost;
    private final int proxyPort;

    RequestThread(String label, String url, String proxyHost, int proxyPort) {
        this.label = label;
        this.url = url;
        this.proxyHost = proxyHost;
        this.proxyPort = proxyPort;
    }

    @Override
    public void run() {
        Log.i(Main.TAG, "begin " + label + " " + url);
        try {
            if (label.endsWith("okhttp")) {
                okhttp();
            } else {
                conscrypt();
            }
        } catch (Throwable error) {
            Log.i(Main.TAG, label + " failed: " + error);
        }
        Log.i(Main.TAG, "end " + label);
    }

    private Proxy proxy() {
        if (proxyHost == null || proxyHost.length() == 0) {
            return null;
        }
        return new Proxy(Proxy.Type.HTTP,
                InetSocketAddress.createUnresolved(proxyHost, proxyPort));
    }

    private void conscrypt() throws Exception {
        URL target = new URL(url);
        URLConnection connection = proxy() == null
                ? target.openConnection()
                : target.openConnection(proxy());
        connection.setConnectTimeout(6000);
        connection.setReadTimeout(6000);
        try (InputStream in = connection.getInputStream()) {
            java.io.ByteArrayOutputStream seen = new java.io.ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int count;
            while ((count = in.read(buffer)) > 0) {
                seen.write(buffer, 0, count);
            }
            String text = seen.toString("UTF-8");
            // The echo report is the whole point of this path: it carries the
            // service's own ja4, computed from the hello we just sent.
            Log.i(Main.TAG, label + " read " + text.length() + " bytes body "
                    + text.substring(0, Math.min(text.length(), 4000)));
        }
    }

    private void okhttp() throws Exception {
        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(java.time.Duration.ofSeconds(6))
                .readTimeout(java.time.Duration.ofSeconds(6))
                .retryOnConnectionFailure(false);
        Proxy proxy = proxy();
        if (proxy != null) {
            builder.proxy(proxy);
        }
        Request request = new Request.Builder().url(url).build();
        try (Response response = builder.build().newCall(request).execute()) {
            ResponseBody body = response.body();
            String text = body == null ? "" : body.string();
            // The echo report is the whole point of this path, so keep enough
            // of it to contain the tls block.
            Log.i(Main.TAG, label + " status " + response.code() + " body "
                    + text.substring(0, Math.min(text.length(), 4000)));
        }
    }
}
