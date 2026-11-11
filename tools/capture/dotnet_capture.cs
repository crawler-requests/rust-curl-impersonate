// Capture the .NET HttpClient fingerprint. SocketsHttpHandler links the
// runtime's OpenSSL on Linux, so the ClientHello differs from libcurl's even
// though both use OpenSSL. Pass "http2" to request HTTP/2 explicitly; the
// default HttpClient version is 1.1.
using System.Net;
using System.Net.Http;

var mode = args.Length > 1 ? args[1] : "http1";
var version = mode == "http2" ? HttpVersion.Version20 : HttpVersion.Version11;
var request = new HttpRequestMessage(HttpMethod.Get, "https://tls.peet.ws/api/all")
{
    Version = version,
    VersionPolicy = HttpVersionPolicy.RequestVersionExact,
};
using var client = new HttpClient();
var response = await client.SendAsync(request);
var body = await response.Content.ReadAsStringAsync();
File.WriteAllText(args[0], body);
Console.Error.WriteLine($"dotnet {Environment.Version} {response.Version}");
