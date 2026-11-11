import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import javax.net.ssl.HttpsURLConnection;
import java.net.URL;
import java.io.InputStream;

// Capture either java.net.http.HttpClient (HTTP/2 by default) or
// HttpsURLConnection (HTTP/1.1).
public final class Capture {
    private static final String URL = "https://tls.peet.ws/api/all";

    public static void main(String[] args) throws Exception {
        String mode = args[0];
        Path out = Path.of(args[1]);
        if (mode.equals("httpclient")) {
            HttpClient client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .connectTimeout(Duration.ofSeconds(20))
                .build();
            HttpRequest request = HttpRequest.newBuilder(URI.create(URL))
                .timeout(Duration.ofSeconds(20))
                .GET()
                .build();
            HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
            Files.write(out, response.body());
            System.err.println("httpclient " + response.version() + " " + response.statusCode());
        } else {
            HttpsURLConnection connection = (HttpsURLConnection) new URL(URL).openConnection();
            connection.setConnectTimeout(20000);
            connection.setReadTimeout(20000);
            try (InputStream in = connection.getInputStream()) {
                Files.write(out, in.readAllBytes());
            }
            System.err.println("urlconnection " + connection.getHeaderField(null) + " " + connection.getResponseCode());
        }
    }

    private Capture() {}
}
