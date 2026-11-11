// Capture the Dart HttpClient fingerprint. Dart's dart:io HTTPS stack uses its
// own BoringSSL build, so its ClientHello differs from both Go and OpenSSL.
import 'dart:convert';
import 'dart:io';

Future<void> main(List<String> args) async {
  final client = HttpClient();
  try {
    final request = await client.getUrl(Uri.parse('https://tls.peet.ws/api/all'));
    final response = await request.close();
    final body = await response.transform(utf8.decoder).join();
    File(args[0]).writeAsStringSync(body);
    stderr.writeln('dart ${response.statusCode}');
  } finally {
    client.close();
  }
}
