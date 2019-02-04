/// This is a library for NTLM authentication in Dart/Flutter.
///
/// NTLM authentication is based on messages being sent to and from the server
/// in HTTP headers. These messages contain the username and hashed versions of
/// the password along with some other information.
///
/// ```dart
/// import 'package:ntlm/ntlm.dart';
///
/// main() {
///   NTLMClient client = new NTLMClient(
///     domain: "",
///     workstation: "LAPTOP",
///     username: "User208",
///     password: "password",
///   );
///
///   client.get("https://example.com/").then((res) {
///     print(res.body);
///   });
/// }
/// ```
library ntlm;

export 'package:ntlm/src/http.dart';
export 'package:ntlm/src/hash.dart';
export 'package:ntlm/src/messages/messages.dart';
