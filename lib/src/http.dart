import 'dart:typed_data';
import 'package:http/http.dart';
import 'package:ntlm/src/messages/messages.dart';

const _wwwAuthenticateHeader = 'www-authenticate';
const _authorizationHeader = 'authorization';

class NTLMClient extends BaseClient {
  /// The NT domain used by this client to authenticate
  String domain;

  /// The NT workstation used by this client to authenticate
  String workstation;

  /// The username of the user trying to authenticate
  final String username;

  /// The password of the user trying to authenticate
  final String? _password;

  /// The password is set
  bool get isPassSet => (_password ?? '') != '';

  /// The lan manager hash of the user's password
  final String? _lmPassword;

  /// The NT hash of the user's password
  final String? _ntPassword;

  /// The prefix for 'www-authenticate'/'authorization' headers (usually
  /// either [kHeaderPrefixNTLM] or [kHeaderPrefixNegotiate])
  String headerPrefix;

  /// The HTTP client used by this NTLMClient to make requests
  late Client _inner;

  /// Creates a new NTLM client
  ///
  /// The [username] is required as is either the [_password]...
  ///
  /// ```dart
  /// NTLMClient client = new NTLMClient(
  ///   username: "User208",
  ///   password: "password",
  /// );
  /// ```
  ///
  /// ...or the [_lmPassword] and the [_ntPassword] in base 64 form.
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
    required String username,
    String? password,
    String? lmPassword,
    String? ntPassword,
    Client? inner,
    this.headerPrefix = kHeaderPrefixNTLM,
  })  : username = username,
        _password = password,
        _ntPassword = ntPassword,
        _lmPassword = lmPassword {
    if (_password == null && (_lmPassword == null || _ntPassword == null)) {
      throw ArgumentError(
        'You must provide a password or the LM and NT hash of a password.',
      );
    }

    _inner = inner ?? Client();
  }

  BaseRequest _copyRequest(BaseRequest request, Uint8List body) =>
      Request(request.method, request.url)
        ..persistentConnection = request.persistentConnection
        ..followRedirects = request.followRedirects
        ..maxRedirects = request.maxRedirects
        ..headers.addAll(request.headers)
        ..bodyBytes = body;

  /// Function that actually does the NTLM authentication.
  ///
  /// This function generates the headers required to authenticate based on
  /// previous responses.
  @override
  Future<StreamedResponse> send(BaseRequest originalReq) async {
    // We need to be able to send a copy of the request with the Type 3 message
    // header attached. Since request bodies can only be streamed once, read the
    // entire body now so we can create request copies later on.
    final body = await originalReq.finalize().toBytes();

    // 1. Send the initial request
    final msg1 = createType1Message(
      domain: domain,
      workstation: workstation,
      headerPrefix: headerPrefix,
    );

    final req2 = _copyRequest(originalReq, body);
    req2.headers[_authorizationHeader] = msg1;
    final res2 = await _inner.send(req2);

    // 2. Parse the Type 2 message
    final res2Authenticate = res2.headers[_wwwAuthenticateHeader];
    // If the initial request was successful or this isn't an NTLM request,
    // return the initial response
    if (res2.statusCode == 200 || res2Authenticate == null) return res2;
    // Servers may support multiple authentication methods so we need to find
    // the correct one
    final res2AuthenticateParts = res2Authenticate.split(',');
    String? rawMsg2;
    for (var res2AuthenticatePart in res2AuthenticateParts) {
      var trimmedPart = res2AuthenticatePart.trim();
      if (trimmedPart.startsWith('$headerPrefix ')) {
        rawMsg2 = trimmedPart;
        break;
      }
    }
    // If this isn't an NTLM request, return the initial response
    if (rawMsg2 == null) return res2;
    final msg2 = parseType2Message(
      rawMsg2,
      headerPrefix: headerPrefix,
    );
    // Discard the body so we can reuse the connection (required by NTLM)
    await res2.stream.drain();

    // 3. Send the authenticated request
    final msg3 = createType3Message(
      msg2,
      domain: domain,
      workstation: workstation,
      username: username,
      password: _password,
      lmPassword: _lmPassword,
      ntPassword: _ntPassword,
      headerPrefix: headerPrefix,
    );

    final req3 = _copyRequest(originalReq, body);
    req3.headers[_authorizationHeader] = msg3;
    final res3 = await _inner.send(req3);

    return res3;
  }

  @Deprecated('Use the `NTLMClient.send` method instead')
  Future<StreamedResponse> multipart(MultipartRequest request) => send(request);
}
