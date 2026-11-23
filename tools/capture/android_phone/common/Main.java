package io.capture.phone;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.webkit.WebView;
import android.webkit.WebViewClient;

/**
 * Drives the TLS stacks of one build so the host-side listener can tell them
 * apart by SNI. Each build links exactly one library version (see build.sh),
 * so a hello captured from `okhttp-3.14.4-okhttp.<base>` is that client's,
 * with no reflection and no class loader tricks in the path.
 *
 * URLs are `<label>-<stack>.<base>`, e.g. `okhttp-3-14-4-okhttp.127-0-0-1
 * .sslip.io`. sslip.io resolves the dotted address back to the listener, so
 * no /etc/hosts edit (which needs root) is involved.
 *
 * The handshakes are meant to fail - the listener never answers - so every
 * step is logged and nothing is retried.
 *
 * No anonymous classes live here on purpose: d8 aborts with an internal
 * NullPointerException when handed a class file for an anonymous inner
 * class, which would make this app unbuildable.
 */
public final class Main extends Activity {
    static final String TAG = "PhoneCap";
    /** The running activity: Cronet's builder needs a Context. */
    static Main instance;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        instance = this;
        String base = getIntent().getStringExtra("base");
        String mode = getIntent().getStringExtra("mode");
        String label = getIntent().getStringExtra("label");
        String proxy = getIntent().getStringExtra("proxy");
        String maxVersion = getIntent().getStringExtra("max-version");
        if (maxVersion != null) {
            Stacks.maxVersion = maxVersion;
        }
        int port = getIntent().getIntExtra("port", 8443);
        if (base == null) {
            // With `adb reverse tcp:8443 tcp:8443` the device's own loopback
            // reaches the listener; the label still tells the stacks apart.
            base = "127-0-0-1.sslip.io";
        }
        if (".".equals(base)) {
            // "-" from the harness: the label alone is the hostname, as
            // listed in the device's /etc/hosts. Used when the name is too
            // long for a DNS label.
            base = "";
        }
        if (mode == null) {
            mode = "all";
        }
        if (label == null) {
            label = "capture";
        }
        Log.i(TAG, "start mode=" + mode + " label=" + label + " base=" + base
                + " port=" + port + " proxy=" + proxy);

        String webviewUrl = getIntent().getStringExtra("webview-url");
        if (webviewUrl != null && webviewUrl.length() > 0) {
            // The echo path for WebView: it cannot use a CONNECT proxy, so
            // it is pointed straight at the service and the report is read
            // out of the page. The listener cannot see a hello this way, so
            // this run is only for HTTP/2 data.
            loadWebView(webviewUrl);
        } else if ("webview".equals(mode)) {
            loadWebView("https://" + label + "-webview." + base + ":" + port + "/");
        } else {
            Thread worker = new Thread(
                    new RunStacks(base, port, mode, label, proxy, this));
            worker.start();
        }
    }

    void loadWebView(String url) {
        Log.i(TAG, "begin webview " + url);
        WebView view = new WebView(this);
        view.getSettings().setJavaScriptEnabled(true);
        view.setWebViewClient(new PageClient());
        view.setWebChromeClient(new PageClient.Title());
        view.loadUrl(url);
        Log.i(TAG, "end webview");
    }

}
