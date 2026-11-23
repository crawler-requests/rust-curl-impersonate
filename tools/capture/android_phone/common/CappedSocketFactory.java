package io.capture.phone;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Forces one fixed TLS protocol on every socket, so a request speaks the
 * version an older Android release would. The platform's own socket factory
 * is kept for everything else; only the protocol list is replaced.
 */
final class CappedSocketFactory extends SSLSocketFactory {
    private final SSLSocketFactory inner;
    private final String protocol;

    CappedSocketFactory(SSLSocketFactory inner) {
        this(inner, "");
    }

    CappedSocketFactory withSct() {
        includeSct = true;
        return this;
    }

    private CappedSocketFactory(SSLSocketFactory inner, String protocol) {
        this.inner = inner;
        this.protocol = protocol;
    }

    static SSLSocketFactory of(javax.net.ssl.HttpsURLConnection connection,
                               String protocol) {
        return new CappedSocketFactory(connection.getSSLSocketFactory(),
                protocol);
    }

    /** Wraps an existing factory, e.g. the one a library built for itself. */
    static SSLSocketFactory of(SSLSocketFactory factory, String protocol) {
        return new CappedSocketFactory(factory, protocol);
    }

    /**
     * Wraps the factory a built client uses, narrowing its protocol list
     * while leaving everything else - ALPN, session tickets - in its hands.
     * The client object is asked for its factory through the only accessor
     * every OkHttp version has.
     */
    static SSLSocketFactory wrappingOkHttpAlpn(Object builtClient,
                                               String protocol) {
        try {
            java.lang.reflect.Method m =
                    builtClient.getClass().getMethod("sslSocketFactory");
            return new CappedSocketFactory(
                    (SSLSocketFactory) m.invoke(builtClient), protocol);
        } catch (Exception error) {
            throw new IllegalStateException("no sslSocketFactory()", error);
        }
    }

    /** The platform's default TLS factory, for libraries that want one. */
    static SSLSocketFactory platformFactory() {
        try {
            return javax.net.ssl.SSLContext.getDefault().getSocketFactory();
        } catch (java.security.NoSuchAlgorithmException unreachable) {
            throw new IllegalStateException("TLS is always available", unreachable);
        }
    }

    /**
     * Accepts every certificate. The listener never answers the handshake,
     * so trust is never exercised; this exists only because a custom socket
     * factory has to be paired with a trust manager.
     */
    static javax.net.ssl.X509TrustManager permissive() {
        return new javax.net.ssl.X509TrustManager() {
            @Override
            public void checkClientTrusted(
                    java.security.cert.X509Certificate[] chain, String auth) {
            }

            @Override
            public void checkServerTrusted(
                    java.security.cert.X509Certificate[] chain, String auth) {
            }

            @Override
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return new java.security.cert.X509Certificate[0];
            }
        };
    }

    /**
     * Turns on Conscrypt's certificate-transparency verification, the private
     * switch behind SSL_enable_signed_cert_timestamps - which makes the
     * client send a signed_certificate_timestamp extension. Both the
     * platform build (com.android.org.conscrypt) and the bundled one
     * (org.conscrypt) keep the parameters in a private field of the engine
     * socket, so the object is found by walking the superclass chain.
     */
    private static void setCtVerification(javax.net.ssl.SSLSocket ssl) {
        try {
            // The parameters object is held in a field called `impl`, whose
            // type is SSLParametersImpl; the name alone is not enough, since
            // other classes have an `impl` of a different type.
            java.lang.reflect.Field field = null;
            for (Class<?> type = ssl.getClass(); type != null;
                    type = type.getSuperclass()) {
                for (java.lang.reflect.Field f : type.getDeclaredFields()) {
                    // The engine socket keeps its parameters in a field
                    // whose type is SSLParametersImpl; on the platform the
                    // class hierarchy is the same, so both builds match.
                    // SocksSocketImpl is java.net.Socket's own impl field,
                    // not the TLS parameters; skip anything java.net.
                    String typeName = f.getType().getName();
                    if (typeName.endsWith("SSLParametersImpl")) {
                        field = f;
                        break;
                    }
                }

                if (field != null) {
                    break;
                }
            }
            if (field == null) {
                StringBuilder names = new StringBuilder();
                for (Class<?> t = ssl.getClass(); t != null; t = t.getSuperclass()) {
                    names.append(t.getSimpleName()).append(':');
                    for (java.lang.reflect.Field f : t.getDeclaredFields()) {
                        names.append(f.getName()).append(' ');
                    }
                    names.append("|");
                }
                throw new NoSuchFieldException(names.toString());
            }
            field.setAccessible(true);
            Object parameters = field.get(ssl);
            parameters.getClass()
                    .getMethod("setCTVerificationEnabled", boolean.class)
                    .invoke(parameters, true);
            android.util.Log.i("PhoneCap", "ct enabled on "
                    + parameters.getClass().getName());
        } catch (Throwable unavailable) {
            android.util.Log.i("PhoneCap", "ct unavailable: " + unavailable);
        }
    }

    /** Ask for a signed_certificate_timestamp extension, as an app can. */
    static boolean includeSct = false;

    private Socket cap(Socket socket) {
        if (socket instanceof SSLSocket) {
            SSLSocket ssl = (SSLSocket) socket;
            if (protocol.length() > 0) {
                ssl.setEnabledProtocols(new String[] {protocol});
            }
            if (includeSct) {
                // Android 9+ exposes this through SSLParameters; on older
                // releases it is absent and the call is skipped.
                try {
                    javax.net.ssl.SSLParameters parameters = ssl.getSSLParameters();
                    java.lang.reflect.Method m = parameters.getClass()
                            .getMethod("setIncludeSCTList", boolean.class);
                    m.invoke(parameters, true);
                    ssl.setSSLParameters(parameters);
                } catch (Throwable absentOnThisRelease) {
                    android.util.Log.i("PhoneCap", "sct request failed: "
                            + absentOnThisRelease);
                }
                setCtVerification(ssl);
            }
        }
        return socket;
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose)
            throws IOException {
        return cap(inner.createSocket(s, host, port, autoClose));
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return inner.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return inner.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        return cap(inner.createSocket(host, port));
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost,
                               int localPort) throws IOException {
        return cap(inner.createSocket(host, port, localHost, localPort));
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return cap(inner.createSocket(host, port));
    }

    @Override
    public Socket createSocket(InetAddress address, int port,
                               InetAddress localAddress, int localPort)
            throws IOException {
        return cap(inner.createSocket(address, port, localAddress, localPort));
    }
}
