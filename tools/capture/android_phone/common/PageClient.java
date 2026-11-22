package io.capture.phone;

import android.util.Log;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.webkit.WebViewClient;

/**
 * Reads the page text back out. When the WebView is pointed straight at a
 * service that echoes its own view of the connection (tls.peet.ws), the page
 * IS the report: without this the run leaves no record of it.
 *
 * The value comes back as the page title, because
 * {@link WebChromeClient#onReceivedTitle} is the only framework callback
 * that hands a plain String over: an evaluateJavascript callback needs
 * ValueCallback&lt;String&gt;, whose class file d8 refuses
 * ("Compilation failed with an internal error").
 *
 * Only the fields this project records go into the title, so one line holds
 * them: the whole report is longer than logcat's 4 KB line limit.
 */
final class PageClient extends WebViewClient {
    @Override
    public void onPageFinished(WebView view, String url) {
        Log.i(Main.TAG, "webview finished " + url);
        view.evaluateJavascript(
                "(function(){try{var d=JSON.parse(document.body.innerText);"
                        + "document.title='REPORT '+JSON.stringify({ja4:d.tls.ja4,"
                        + "http2:d.http2,http_version:d.http_version});}"
                        + "catch(e){document.title='REPORT ERROR '+e;}})()", null);
    }

    /** Logs the report the page put in its title. */
    static final class Title extends WebChromeClient {
        @Override
        public void onReceivedTitle(WebView view, String title) {
            if (title != null && title.startsWith("REPORT ")) {
                Log.i(Main.TAG, "webview report " + title.substring(7));
            }
        }
    }
}
