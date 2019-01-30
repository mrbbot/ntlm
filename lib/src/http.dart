import 'package:http/http.dart';
import 'package:meta/meta.dart';
import 'dart:io';
import 'dart:async';
import 'package:ntlm/src/messages/messages.dart';

class NTLMClient {
  String domain;
  String workstation;
  String username;
  String password;
  String lmPassword;
  String ntPassword;

  NTLMClient({
    this.domain = "",
    this.workstation = "",
    @required this.username,
    this.password = null,
    this.lmPassword = null,
    this.ntPassword = null,
  }) {
    if (this.password == null &&
        (this.lmPassword == null || this.ntPassword == null)) {
      throw new ArgumentError(
        "You must provide a password or the LM and NT hash of a password.",
      );
    }
  }

  Future<Response> get(String url, {Map<String, String> headers}) async {
    if (headers == null) {
      headers = new Map<String, String>();
    }

    var client = Client();

    Response res0 = await client.get(url, headers: headers);
    if (res0.statusCode == 200 ||
        !res0.headers[HttpHeaders.wwwAuthenticateHeader].contains("NTLM"))
      return res0;

    String msg1 = createType1Message(
      domain: domain,
      workstation: workstation,
    );
    Response res2 = await client.get(url,
        headers: {
          HttpHeaders.authorizationHeader: msg1,
        }..addAll(headers));

    String res2Authenticate = res2.headers[HttpHeaders.wwwAuthenticateHeader];
    if (!res2Authenticate.startsWith("NTLM ")) return res0;
    Type2Message msg2 = parseType2Message(res2Authenticate);

    String msg3 = createType3Message(
      msg2,
      domain: domain,
      workstation: workstation,
      username: username,
      password: password,
      lmPassword: lmPassword,
      ntPassword: ntPassword,
    );
    Response res3 = await client.get(url,
        headers: {
          HttpHeaders.authorizationHeader: msg3,
        }..addAll(headers));

    client.close();

    return res3;
  }
}
