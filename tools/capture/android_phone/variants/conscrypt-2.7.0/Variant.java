package io.capture.phone;

import java.io.InputStream;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.security.Provider;
import java.security.Security;

import org.conscrypt.OpenSSLProvider;

/**
 * Conscrypt 2.7.0 as a JCA provider. Installing it at priority 1 makes the
 * next HttpsURLConnection use it instead of the platform's own Conscrypt,
 * which is why the label says the version - the hello is this build's.
 */
final class Variant {
    private Variant() {
    }

    static void request(String kind, String url, Proxy proxy) throws Exception {
        if (!"conscrypt".equals(kind)) {
            throw new UnsupportedOperationException("this build links Conscrypt only");
        }
        Provider provider = new OpenSSLProvider();
        synchronized (Security.class) {
            Security.removeProvider(provider.getName());
            Security.insertProviderAt(provider, 1);
        }
        android.util.Log.i(Main.TAG, "conscrypt provider " + provider.getName()
                + " " + provider.getVersion());
        try {
            URLConnection connection = proxy == null
                    ? new URL(url).openConnection()
                    : new URL(url).openConnection(proxy);
            connection.setConnectTimeout(6000);
            connection.setReadTimeout(6000);
            try (InputStream in = connection.getInputStream()) {
                byte[] buffer = new byte[8192];
                while (in.read(buffer) > 0) {
                    // The body is not used; reading keeps the socket up.
                }
            }
        } finally {
            synchronized (Security.class) {
                Security.removeProvider(provider.getName());
            }
        }
    }
}
