package io.capture.phone;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.webkit.WebView;
import android.webkit.WebViewClient;

/**
 * Drives three TLS stacks in turn so the host-side listener can tell them
 * apart by SNI:
 *
 *   conscrypt.<base>   the platform stack via HttpsURLConnection
 *   okhttp.<base>      the app-bundled OkHttp 4.12
 *   webview.<base>     the system WebView (Chromium)
 *
 * Each URL resolves to the listener's address through sslip.io, so the SNI
 * carries the label and no /etc/hosts edit (which needs root) is involved.
 * The handshakes are meant to fail - the listener never answers - so every
 * step is logged and nothing is retried.
 *
 * No anonymous classes live here on purpose: d8 aborts with an internal
 * NullPointerException when it is handed a class file for an anonymous inner
 * class, which would make this app unbuildable.
 */
public final class Main extends Activity {
    static final String TAG = "PhoneCap";

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        String base = getIntent().getStringExtra("base");
        String mode = getIntent().getStringExtra("mode");
        String proxy = getIntent().getStringExtra("proxy");
        int port = getIntent().getIntExtra("port", 8443);
        if (base == null) {
            // With `adb reverse tcp:8443 tcp:8443` the phone's own loopback
            // reaches the listener; the label still tells the stacks apart.
            base = "127-0-0-1.sslip.io";
        }
        if (mode == null) {
            mode = "all";
        }
        Log.i(TAG, "start mode=" + mode + " base=" + base + " port=" + port
                + " proxy=" + proxy);

        if ("webview".equals(mode)) {
            loadWebView("https://webview." + base + ":" + port + "/");
        } else {
            Thread worker = new Thread(
                    new RunStacks(base, port, mode, proxy, this));
            worker.start();
        }
    }

    void loadWebView(String url) {
        Log.i(TAG, "begin webview " + url);
        WebView view = new WebView(this);
        view.getSettings().setJavaScriptEnabled(true);
        view.setWebViewClient(new WebViewClient());
        view.loadUrl(url);
        Log.i(TAG, "end webview");
    }
}
