import 'package:ntlm/ntlm.dart';

main() {
  NTLMClient client = new NTLMClient(
    domain: "",
    workstation: "LAPTOP",
    username: "User208",
    password: "password",
  );

  client.get("https://example.com/").then((res) {
    print(res.body);
  });
}
