package io.capture.phone;

import android.util.Log;

/**
 * The sequence the probe runs, on a worker thread so the platform refuses no
 * request. Every URL carries this build's label in its SNI, plus the stack
 * it used, so one capture directory can hold several builds' results.
 */
public final class RunStacks implements Runnable {
    private static final long GAP_MS = 1500;

    private final String base;
    private final int port;
    private final String mode;
    private final String label;
    private final String proxy;
    private final Main activity;

    RunStacks(String base, int port, String mode, String label, String proxy,
              Main activity) {
        this.base = base;
        this.port = port;
        this.mode = mode;
        this.label = label;
        this.proxy = proxy;
        this.activity = activity;
    }

    @Override
    public void run() {
        sleep(400);
        try {
            for (String kind : mode.split(",")) {
                String name = kind.trim();
                if (name.length() == 0) {
                    continue;
                }
                // With no base the label is the whole hostname; a trailing
                // dot would make OkHttp reject the URL.
                String suffix = base.length() == 0 ? "" : "." + base;
                if ("webview".equals(name)) {
                    Log.i(Main.TAG, "webview goes to the UI thread");
                    activity.runOnUiThread(new WebViewLoader(activity,
                            "https://" + label + "-webview" + suffix + ":"
                                    + port + "/"));
                } else {
                    Stacks.run(label + "-" + name, name,
                            "https://" + label + "-" + name + suffix + ":"
                                    + port + "/", proxy);
                }
                sleep(GAP_MS);
            }
            if (proxy != null && proxy.length() > 0) {
                // The echo path: this machine's proxy relays to the real
                // service, so its report is computed server-side, not by our
                // parser.
                for (String kind : mode.split(",")) {
                    String name = kind.trim();
                    if (name.length() == 0 || "webview".equals(name)) {
                        continue;
                    }
                    Stacks.run("echo-" + label + "-" + name, name,
                            "https://tls.peet.ws/api/all", proxy);
                    sleep(GAP_MS);
                }
            }
        } catch (Exception error) {
            Log.i(Main.TAG, "sequence failed: " + error);
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
