import 'dart:convert';

import 'package:http/http.dart';
import 'dart:io';
import 'dart:async';
import 'package:ntlm/src/messages/messages.dart';

/// Callback for when a request needs to be made.
///
/// This is used to reduce duplication of the NTLM authentication code for all
/// HTTP methods.
typedef _RequestCallback = Future<Response> Function(
  Map<String, String> ntlmHeaders,
);

class NTLMClient {
  /// The NT domain used by this client to authenticate
  String domain;
  /// The NT workstation used by this client to authenticate
  String workstation;
  /// The username of the user trying to authenticate
  String username;
  /// The password of the user trying to authenticate
  String password;
  /// The lan manager hash of the user's password
  String lmPassword;
  /// The NT hash of the user's password
  String ntPassword;
  /// The HTTP client used by this NTLMClient to make requests
  Client _inner;

  /// Creates a new NTLM client
  ///
  /// The [username] is required as is either the [password]...
  ///
  /// ```dart
  /// NTLMClient client = new NTLMClient(
  ///   username: "User208",
  ///   password: "password",
  /// );
  /// ```
  ///
  /// ...or the [lmPassword] and the [ntPassword] in base 64 form.
  ///
  /// ```dart
  /// String lmPassword = lmHash("password");
  /// String ntPassword = ntHash("password");
  ///
  /// NTLMClient client = new NTLMClient(
  ///   username: "User208",
  ///   lmPassword: lmPassword,
  ///   ntPassword: ntPassword,
  /// );
  /// ```
  ///
  /// You can optionally pass in an [inner] client to make all the HTTP
  /// requests.
  NTLMClient({
    this.domain = "",
    this.workstation = "",
    this.username,
    this.password = null,
    this.lmPassword = null,
    this.ntPassword = null,
    Client inner,
  }) {
    if (this.password == null &&
        (this.lmPassword == null || this.ntPassword == null)) {
      throw new ArgumentError(
        "You must provide a password or the LM and NT hash of a password.",
      );
    }
  
    this._inner = inner ?? Client();
  }

  /// Function that does the handles NTLM authentication.
  ///
  /// With the provided additional [headers], this function generates the
  /// headers required to authenticate based on previous responses. The
  /// responses are then retrieved through the [request] callback.
  Future<Response> _ntlm({
    Map<String, String> headers,
    _RequestCallback request,
  }) async {
    if (headers == null) {
      headers = Map<String, String>();
    }

    Response res0 = await request(headers);
    if (res0.statusCode == 200 ||
        !res0.headers[HttpHeaders.wwwAuthenticateHeader].contains("NTLM"))
      return res0;

    String msg1 = createType1Message(
      domain: domain,
      workstation: workstation,
    );

    Response res2 = await request({
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

    Response res3 = await request({
      HttpHeaders.authorizationHeader: msg3,
    }..addAll(headers));

    return res3;
  }

  /// Sends a HTTP GET request to the [url] authenticating with NTLM.
  Future<Response> get(url, {Map<String, String> headers}) async {
    return _ntlm(
      headers: headers,
      request: (ntlmHeaders) => _inner.get(
            url,
            headers: ntlmHeaders,
          ),
    );
  }

  /// Sends a HTTP POST request to the [url] authenticating with NTLM.
  Future<Response> post(url,
      {Map<String, String> headers, body, Encoding encoding}) {
    return _ntlm(
      headers: headers,
      request: (ntlmHeaders) => _inner.post(
            url,
            headers: ntlmHeaders,
            body: body,
            encoding: encoding,
          ),
    );
  }

  /// Sends a HTTP PATCH request to the [url] authenticating with NTLM.
  Future<Response> patch(url,
      {Map<String, String> headers, body, Encoding encoding}) {
    return _ntlm(
      headers: headers,
      request: (ntlmHeaders) => _inner.patch(
            url,
            headers: ntlmHeaders,
            body: body,
            encoding: encoding,
          ),
    );
  }

  /// Sends a HTTP PUT request to the [url] authenticating with NTLM.
  Future<Response> put(url,
      {Map<String, String> headers, body, Encoding encoding}) {
    return _ntlm(
      headers: headers,
      request: (ntlmHeaders) => _inner.put(
            url,
            headers: ntlmHeaders,
            body: body,
            encoding: encoding,
          ),
    );
  }

  /// Sends a HTTP HEAD request to the [url] authenticating with NTLM.
  Future<Response> head(url, {Map<String, String> headers}) {
    return _ntlm(
      headers: headers,
      request: (ntlmHeaders) => _inner.head(
            url,
            headers: ntlmHeaders,
          ),
    );
  }

  /// Sends a HTTP DELETE request to the [url] authenticating with NTLM.
  Future<Response> delete(url, {Map<String, String> headers}) {
    return _ntlm(
      headers: headers,
      request: (ntlmHeaders) => _inner.delete(
            url,
            headers: ntlmHeaders,
          ),
    );
  }
}
