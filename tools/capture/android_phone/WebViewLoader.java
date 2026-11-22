package io.capture.phone;

/** Loads one URL in the system WebView, on the UI thread. */
public final class WebViewLoader implements Runnable {
    private final Main activity;
    private final String url;

    WebViewLoader(Main activity, String url) {
        this.activity = activity;
        this.url = url;
    }

    @Override
    public void run() {
        activity.loadWebView(url);
    }
}
