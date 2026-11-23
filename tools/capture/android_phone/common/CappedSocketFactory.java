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

    private static Object serverContext() throws Exception {
        Class<?> implClass = Class.forName("org.conscrypt.SSLParametersImpl");
        return implClass.getDeclaredMethod("getServerSessionContext")
                .invoke(null);
    }

    /**
     * The client and server session contexts of the bundled Conscrypt. They
     * are taken from a real SSLContext built with its provider, because the
     * static accessors are not static and the constructor needs them.
     */
    private static Object[] sessionContexts() throws Exception {
        // The bundled Conscrypt is only on the variant class path, so it is
        // reached by reflection here and the platform build still compiles.
        java.security.Provider provider = (java.security.Provider) Class
                .forName("org.conscrypt.OpenSSLProvider")
                .getConstructor().newInstance();
        javax.net.ssl.SSLContext context =
                javax.net.ssl.SSLContext.getInstance("TLS", provider);
        context.init(null, new javax.net.ssl.TrustManager[] {permissive()},
                new java.security.SecureRandom());
        Object spi = context.getProvider().getService("SSLContext", "TLS");
        Class<?> implClass = Class.forName("org.conscrypt.SSLParametersImpl");
        Object client = implClass.getDeclaredMethod("getClientSessionContext")
                .invoke(null);
        return new Object[] {client, null};
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
                    // Only the field whose type is a Conscrypt
                    // SSLParametersImpl carries the CT switch; java.net's
                    // SocksSocketImpl also has an `impl`, so the type check
                    // is what tells them apart.
                    String typeName = f.getType().getName();
                    // Android renames or erases this type in places, so the
                    // field NAME is the reliable marker; the type check is a
                    // secondary guard for the bundled build.
                    if (f.getName().equals("sslParameters")
                            || typeName.endsWith("SSLParametersImpl")) {
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

    /**
     * A Conscrypt factory, from the bundled jar, whose parameters have CT
     * verification on - the setting that makes the client send an SCT
     * extension. Uses getDefault() and setCTVerificationEnabled(), both
     * internal but reachable on the Maven build.
     */
    static SSLSocketFactory ctWithBundled(String[] alpn) {
        try {
            Class<?> implClass = Class.forName("org.conscrypt.SSLParametersImpl");
            {
                StringBuilder m = new StringBuilder("methods:");
                for (java.lang.reflect.Method mm : implClass.getDeclaredMethods()) {
                    if (mm.getName().toLowerCase().contains("ct")) {
                        m.append(' ').append(mm.getName()).append('/')
                         .append(mm.getParameterCount());
                    }
                }
                android.util.Log.i("PhoneCap", m.toString());
            }
            // (KeyManager[], TrustManager[], SecureRandom,
            //  ClientSessionContext, ServerSessionContext, String[])
            Object[] contexts = sessionContexts();
            java.lang.reflect.Constructor<?> ctor = implClass.getDeclaredConstructor(
                    javax.net.ssl.KeyManager[].class,
                    javax.net.ssl.TrustManager[].class,
                    java.security.SecureRandom.class,
                    Class.forName("org.conscrypt.ClientSessionContext"),
                    Class.forName("org.conscrypt.ServerSessionContext"),
                    String[].class);
            ctor.setAccessible(true);
            Object impl = ctor.newInstance(
                    new javax.net.ssl.KeyManager[0],
                    new javax.net.ssl.TrustManager[] {permissive()},
                    new java.security.SecureRandom(),
                    contexts[0], contexts[1],
                    new String[] {"TLSv1.3", "TLSv1.2"});
            // getMethod only finds public members; Conscrypt keeps this
            // package-private, so getDeclaredMethod plus setAccessible is
            // the way in.
            java.lang.reflect.Method ct = implClass.getDeclaredMethod(
                    "setCTVerificationEnabled", boolean.class);
            ct.setAccessible(true);
            ct.invoke(impl, true);
            if (alpn != null && alpn.length > 0) {
                for (String name : new String[] {"setApplicationProtocols", "setApplicationProtocolSelector"}) {
                    try {
                        java.lang.reflect.Method m = implClass.getDeclaredMethod(
                                name, String[].class);
                        m.setAccessible(true);
                        m.invoke(impl, (Object) alpn);
                        break;
                    } catch (NoSuchMethodException next) {
                        // Try the next name.
                    }
                }
            }
            Class<?> factoryClass =
                    Class.forName("org.conscrypt.OpenSSLSocketFactoryImpl");
            {
                StringBuilder m = new StringBuilder("factoryctors:");
                for (java.lang.reflect.Constructor<?> cc : factoryClass.getDeclaredConstructors()) {
                    m.append('(');
                    for (Class<?> t : cc.getParameterTypes()) {
                        m.append(t.getSimpleName()).append(',');
                    }
                    m.append(')');
                }
                android.util.Log.i("PhoneCap", m.toString());
            }
            java.lang.reflect.Constructor<?> factoryConstructor =
                    factoryClass.getDeclaredConstructor(implClass);
            factoryConstructor.setAccessible(true);
            try {
                return (SSLSocketFactory) factoryConstructor.newInstance(impl);
            } catch (Throwable needsContext) {
                // The no-arg form supplies its own default session context.
                java.lang.reflect.Constructor<?> bare =
                        factoryClass.getDeclaredConstructor();
                bare.setAccessible(true);
                return (SSLSocketFactory) bare.newInstance();
            }
        } catch (Throwable unavailable) {
            StringBuilder sig = new StringBuilder();
            try {
                for (java.lang.reflect.Constructor<?> c : Class
                        .forName("org.conscrypt.SSLParametersImpl").getDeclaredConstructors()) {
                    sig.append('(');
                    for (Class<?> t : c.getParameterTypes()) {
                        sig.append(t.getSimpleName()).append(',');
                    }
                    sig.append(')');
                }
            } catch (Throwable e3) {
                sig.append(e3);
            }
            android.util.Log.i("PhoneCap", "ct factory failed: " + unavailable
                    + " ctors=" + sig);
            return null;
        }
    }


    /** The platform's default TLS factory, for libraries that want one. */
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
