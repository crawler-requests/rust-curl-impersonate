package io.capture.phone;

import android.util.Log;

import org.chromium.net.CronetEngine;
import org.chromium.net.UrlRequest;

import java.net.Proxy;
import java.nio.ByteBuffer;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Cronet 119.0.6045.31, linked directly. The engine is started with its own
 * executor so `start()` never touches the UI thread, and the call is waited
 * on: a handshake failure is the expected outcome because the listener never
 * answers.
 */
final class Variant {
    private static CountDownLatch DONE = new CountDownLatch(1);
    private static final StringBuilder BODY = new StringBuilder();

    private Variant() {
    }

    static void request(String kind, String url, Proxy proxy) throws Exception {
        if (!"cronet".equals(kind)) {
            throw new UnsupportedOperationException("this build links Cronet only");
        }
        // A fresh latch per request: the listener deliberately fails
        // the first handshake, and a reused latch would let that
        // failure end the echo request before it started.
        DONE = new CountDownLatch(1);
        BODY.setLength(0);
        Executor executor = Executors.newSingleThreadExecutor();
        CronetEngine engine = new CronetEngine.Builder(Main.instance).build();
        Log.i(Main.TAG, "cronet engine " + engine.getVersionString());
        UrlRequest.Callback callback = new Callback();
        UrlRequest request = engine.newUrlRequestBuilder(url, callback, executor)
                .build();
        request.start();
        DONE.await(25, TimeUnit.SECONDS);
        // The echo path returns tls.peet.ws's report; it is only useful if
        // it reaches the log.
        if (BODY.length() > 0) {
            Log.i(Main.TAG, "cronet body "
                    + BODY.substring(0, BODY.length()));
        }
        try {
            engine.shutdown();
        } catch (IllegalStateException busy) {
            // A cancelled request still counts as running; the hello is
            // already on the wire and that is the capture.
            Log.i(Main.TAG, "cronet shutdown skipped: " + busy);
        }
    }

    static final class Callback extends UrlRequest.Callback {
        @Override
        public void onRedirectReceived(UrlRequest request,
                                       org.chromium.net.UrlResponseInfo info,
                                       String newLocationUrl) {
            request.followRedirect();
        }

        @Override
        public void onResponseStarted(UrlRequest request,
                                      org.chromium.net.UrlResponseInfo info) {
            request.read(ByteBuffer.allocateDirect(16384));
        }

        @Override
        public void onReadCompleted(UrlRequest request,
                                    org.chromium.net.UrlResponseInfo info,
                                    ByteBuffer byteBuffer) {
            byteBuffer.flip();
            byte[] chunk = new byte[byteBuffer.remaining()];
            byteBuffer.get(chunk);
            BODY.append(new String(chunk, java.nio.charset.StandardCharsets.UTF_8));
            // The same buffer is reused for the next read, so it has to be
            // emptied first; Cronet rejects a full one.
            byteBuffer.clear();
            request.read(byteBuffer);
        }

        @Override
        public void onSucceeded(UrlRequest request,
                                org.chromium.net.UrlResponseInfo info) {
            Log.i(Main.TAG, "cronet succeeded");
            DONE.countDown();
        }

        @Override
        public void onFailed(UrlRequest request,
                             org.chromium.net.UrlResponseInfo info,
                             org.chromium.net.CronetException error) {
            Log.i(Main.TAG, "cronet failed: " + error);
            DONE.countDown();
        }

        @Override
        public void onCanceled(UrlRequest request,
                               org.chromium.net.UrlResponseInfo info) {
            DONE.countDown();
        }
    }
}
