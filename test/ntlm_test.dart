import 'package:test/test.dart';
import 'package:http/http.dart' as http;
import 'package:ntlm/ntlm.dart';
import 'credentials.dart' as credentials;

void main() {
  test("client", () async {
    NTLMClient client = new NTLMClient(
      domain: "",
      workstation: "",
      username: credentials.username,
      //password: credentials.password,
      lmPassword: lmHash(credentials.password),
      ntPassword: ntHash(credentials.password),
    );

    http.Response res = await client.get(credentials.url);
    print("Body: ${res.body} Headers: ${res.headers}");
    expect(res.statusCode, 200);
  });
}
