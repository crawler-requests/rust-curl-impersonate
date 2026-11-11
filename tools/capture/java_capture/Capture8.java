import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

// Capture the Java 8 HttpsURLConnection fingerprint. Java 8 lacks
// java.net.http.HttpClient and Path.of, so this is a separate, URL-only
// capture: read the body, then write it out (buffered, like the other
// captures) so the container can hand it back to the host.
public final class Capture8 {
    private static final String URL = "https://tls.peet.ws/api/all";

    public static void main(String[] args) throws Exception {
        String mode = args[0];
        File out = new File(args[1]);
        HttpsURLConnection connection = (HttpsURLConnection) new URL(URL).openConnection();
        connection.setConnectTimeout(20000);
        connection.setReadTimeout(20000);
        try (InputStream in = connection.getInputStream();
             OutputStream os = new java.io.FileOutputStream(out)) {
            byte[] buffer = new byte[8192];
            for (int read; (read = in.read(buffer)) != -1; ) {
                os.write(buffer, 0, read);
            }
        }
        System.err.println(mode + " " + connection.getResponseCode());
    }
}