import 'dart:convert';

import 'package:http/http.dart';
import 'package:meta/meta.dart';
import 'dart:io';
import 'dart:async';
import 'package:ntlm/src/messages/messages.dart';

typedef _RequestCallback = Future<Response> Function(
  Map<String, String> ntlmHeaders,
);

class NTLMClient {
  String domain;
  String workstation;
  String username;
  String password;
  String lmPassword;
  String ntPassword;
  Client _inner;

  NTLMClient({
    this.domain = "",
    this.workstation = "",
    @required this.username,
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

  Future<Response> _ntlm({
    Map<String, String> headers,
    _RequestCallback request,
  }) async {
    if (headers == null) {
      headers = Map<String, String>();
    }

    Response res0 = await request(headers);
    if (res0.statusCode == 200 ||
        res0.headers[HttpHeaders.wwwAuthenticateHeader] != "NTLM") return res0;

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

  Future<Response> get(url, {Map<String, String> headers}) async {
    return _ntlm(
      headers: headers,
      request: (ntlmHeaders) => _inner.get(
            url,
            headers: ntlmHeaders,
          ),
    );
  }

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

  Future<Response> head(url, {Map<String, String> headers}) {
    return _ntlm(
      headers: headers,
      request: (ntlmHeaders) => _inner.head(
            url,
            headers: ntlmHeaders,
          ),
    );
  }

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
