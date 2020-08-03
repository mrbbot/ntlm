import 'dart:async';
import 'dart:convert';
import 'package:http/http.dart';
import 'package:ntlm/src/messages/messages.dart';

const _wwwAuthenticateHeader = 'www-authenticate';
const _authorizationHeader = 'authorization';

/// Callback for when a request needs to be made.
///
/// This is used to reduce duplication of the NTLM authentication code for all
/// HTTP methods.
typedef _RequestCallback<R extends BaseResponse> = Future<R> Function(
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

  /// The prefix for the www-authenticaate / authorization header
  /// Usually either of 'NTLM' or 'Negotiate'
  String headerPrefix;

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
    this.domain = '',
    this.workstation = '',
    this.username,
    this.password,
    this.lmPassword,
    this.ntPassword,
    Client inner,
    this.headerPrefix = 'NTLM',
  }) {
    if (password == null && (lmPassword == null || ntPassword == null)) {
      throw ArgumentError(
        'You must provide a password or the LM and NT hash of a password.',
      );
    }

    _inner = inner ?? Client();
  }

  /// Function that does the handles NTLM authentication.
  ///
  /// With the provided additional [headers], this function generates the
  /// headers required to authenticate based on previous responses. The
  /// responses are then retrieved through the [request] callback.
  Future<R> _ntlm<R extends BaseResponse>({
    Map<String, String> headers,
    _RequestCallback<R> request,
  }) async {
    headers ??= <String, String>{};

    var res0 = await request(headers);
    if (res0.statusCode == 200 ||
        !res0.headers.containsKey(_wwwAuthenticateHeader) ||
        !res0.headers[_wwwAuthenticateHeader].contains(headerPrefix)) {
      return res0;
    }

    var msg1 = createType1Message(
      domain: domain,
      workstation: workstation,
      headerPrefix: headerPrefix
    );

    var res2 = await request({
      _authorizationHeader: msg1,
    }..addAll(headers));

    var res2Authenticate = res2.headers[_wwwAuthenticateHeader];
    var res2AuthenticateParts = res2Authenticate.split(',');
    String rawMsg2;
    for (var res2AuthenticatePart in res2AuthenticateParts) {
      var trimmedPart = res2AuthenticatePart.trim();
      if (trimmedPart.startsWith('${headerPrefix} ')) {
        rawMsg2 = trimmedPart;
        break;
      }
    }

    if (rawMsg2 == null) return res0;
    var msg2 = parseType2Message(rawMsg2, headerPrefix);

    var msg3 = createType3Message(
      msg2,
      domain: domain,
      workstation: workstation,
      username: username,
      password: password,
      lmPassword: lmPassword,
      ntPassword: ntPassword,
      headerPrefix: headerPrefix
    );

    var res3 = await request({
      _authorizationHeader: msg3,
    }..addAll(headers));

    return res3;
  }

  /// Sends a HTTP GET request to the [url] authenticating with NTLM.
  Future<Response> get(url, {Map<String, String> headers}) async {
    return _ntlm<Response>(
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
    return _ntlm<Response>(
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
    return _ntlm<Response>(
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
    return _ntlm<Response>(
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
    return _ntlm<Response>(
      headers: headers,
      request: (ntlmHeaders) => _inner.head(
        url,
        headers: ntlmHeaders,
      ),
    );
  }

  /// Sends a HTTP DELETE request to the [url] authenticating with NTLM.
  Future<Response> delete(url, {Map<String, String> headers}) {
    return _ntlm<Response>(
      headers: headers,
      request: (ntlmHeaders) => _inner.delete(
        url,
        headers: ntlmHeaders,
      ),
    );
  }

  /// Sends a MultipartRequest authenticating with NTLM
  Future<StreamedResponse> multipart(MultipartRequest request) {
    return _ntlm<StreamedResponse>(
      headers: request.headers,
      request: (ntlmHeaders) {
        var copy = MultipartRequest(request.method, request.url)
          ..headers.addAll(ntlmHeaders)
          ..fields.addAll(request.fields)
          ..files.addAll(request.files);
        return _inner.send(copy);
      },
    );
  }
}
