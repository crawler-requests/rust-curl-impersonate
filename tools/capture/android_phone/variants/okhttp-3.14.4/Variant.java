package io.capture.phone;

import java.net.Proxy;
import java.util.concurrent.TimeUnit;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/** OkHttp 3.14.4, linked directly so the captured hello is certainly its. */
final class Variant {
    private Variant() {
    }

    static void request(String kind, String url, Proxy proxy) throws Exception {
        if (!"okhttp".equals(kind)) {
            throw new UnsupportedOperationException("this build links OkHttp only");
        }
        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(6, TimeUnit.SECONDS)
                .readTimeout(6, TimeUnit.SECONDS)
                .retryOnConnectionFailure(false);
        if (proxy != null) {
            builder.proxy(proxy);
        }
        Request request = new Request.Builder().url(url).build();
        Response response = builder.build().newCall(request).execute();
        try {
            // The echo path returns tls.peet.ws's own report; logging the
            // body is what makes that server-side check available.
            String body = response.body() == null ? "" : response.body().string();
            android.util.Log.i(Main.TAG, "okhttp status " + response.code()
                    + " body " + body.substring(0, Math.min(body.length(), 6000)));
        } finally {
            response.close();
        }
    }
}
