package io.capture.phone;

import android.util.Log;

/**
 * The sequence the probe runs, on a worker thread so the platform refuses
 * no request. Each stack is given its own hostname; the gap leaves room for
 * the listener to write one capture before the next hello arrives.
 */
public final class RunStacks implements Runnable {
    private static final long GAP_MS = 1500;

    private final String base;
    private final int port;
    private final String mode;
    private final String proxy;
    private final Main activity;

    RunStacks(String base, int port, String mode, String proxy, Main activity) {
        this.base = base;
        this.port = port;
        this.mode = mode;
        this.proxy = proxy;
        this.activity = activity;
    }

    @Override
    public void run() {
        sleep(400);
        if (mode.equals("all") || mode.equals("conscrypt")) {
            new RequestThread("conscrypt",
                    "https://conscrypt." + base + ":" + port + "/", null, 0).run();
            sleep(GAP_MS);
        }
        if (mode.equals("all") || mode.equals("okhttp")) {
            new RequestThread("okhttp",
                    "https://okhttp." + base + ":" + port + "/", null, 0).run();
            sleep(GAP_MS);
        }
        if (proxy != null && proxy.length() > 0) {
            String[] parts = proxy.split(":");
            int proxyPort = Integer.parseInt(parts[1]);
            // The echo path: this machine's proxy relays to the real service,
            // so its report is computed server-side, not by our parser.
            new RequestThread("echo-okhttp", "https://tls.peet.ws/api/all",
                    parts[0], proxyPort).run();
            sleep(GAP_MS);
            new RequestThread("echo-conscrypt", "https://tls.peet.ws/api/all",
                    parts[0], proxyPort).run();
            sleep(GAP_MS);
        }
        if (mode.equals("all")) {
            Log.i(Main.TAG, "webview goes to the UI thread");
            activity.runOnUiThread(new WebViewLoader(activity,
                    "https://webview." + base + ":" + port + "/"));
        }
        Log.i(Main.TAG, "sequence done");
    }

    static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException ignored) {
        }
    }
}
