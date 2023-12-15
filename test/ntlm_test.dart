import 'dart:convert';
import 'dart:io' show Platform;

import 'package:http/http.dart' as http;
import 'package:http_parser/http_parser.dart' as http_parser;
import 'package:ntlm/ntlm.dart';
import 'package:test/test.dart';

/// The environment variable `NTLM_TEST_URL` should be set to the URL of a
/// server that accepts GET, HEAD, POST, PATCH, PUT and DELETE requests to /,
/// responding with a JSON object containing the following keys:
///
/// - `method`: uppercase method name
/// - `headers`: object mapping header key to array of values
/// - `user`: string ending with username of authenticated user
/// - `body`: string containing request body or null if there was none
///
/// An example `GET /` response would look like:
/// ```
/// {
///   "method": "GET",
///   "headers": {
///     "Authorization": ["NTLM ..."],
///   },
///   "user": "DOMAIN\\test",
///   "body": null
/// }
/// ```
///
/// `NTLM_TEST_USERNAME` and `NTLM_TEST_PASSWORD` should be set to credentials
/// of an account with access to this server.
void main() {
  var url = Uri.parse(Platform.environment['NTLM_TEST_URL']!);
  var username = Platform.environment['NTLM_TEST_USERNAME']!;
  var password = Platform.environment['NTLM_TEST_PASSWORD']!;

  var client = NTLMClient(
    domain: '',
    workstation: '',
    username: username,
    //password: password,
    lmPassword: lmHash(password),
    ntPassword: ntHash(password),
  );

  test('NTLMClient.get() requests public sites', () async {
    var res = await client.get(Uri.parse('https://mrbbot.dev'));
    expect(res.statusCode, 200);
  });

  test('NTLMClient.get() authenticates the request', () async {
    var res = await client.get(url);
    _expectResponse(res, 'GET', username, []);
  });

  test('NTLMClient.head() authenticates the request', () async {
    var res = await client.head(url);
    expect(res.statusCode, 200);
  });

  test('NTLMClient.post() authenticates the request', () async {
    var res = await client.post(url, body: 'Test Body');
    _expectResponse(res, 'POST', username, ['Test Body']);
  });

  test('NTLMClient.patch() authenticates the request', () async {
    var res = await client.patch(url, body: 'Test Body');
    _expectResponse(res, 'PATCH', username, ['Test Body']);
  });

  test('NTLMClient.put() authenticates the request', () async {
    var res = await client.put(url, body: 'Test Body');
    _expectResponse(res, 'PUT', username, ['Test Body']);
  });

  test('NTLMClient.delete() authenticates the request', () async {
    var res = await client.delete(url);
    _expectResponse(res, 'DELETE', username, []);
  });

  test('NTLMClient.multipart() authenticates the request', () async {
    var request = http.MultipartRequest('POST', url)
      ..fields['data'] = 'Test Data'
      ..files.add(http.MultipartFile.fromString(
        'file',
        'Test File',
        filename: 'test.txt',
        contentType: http_parser.MediaType('text', 'plain'),
      ));
    var res = await http.Response.fromStream(await client.send(request));
    _expectResponse(
      res,
      'POST',
      username,
      ['Test Data', 'Test File', 'test.txt', 'text/plain'],
    );
  });
}

void _expectResponse(
  http.Response res,
  String method,
  String username,
  List<String> bodySegments,
) {
  print('--> $method:\nHeaders: ${res.headers}\nBody: ${res.body}\n\n');
  expect(res.statusCode, 200);
  Map<String, dynamic> body = json.decode(res.body);
  expect(body['method'], method);
  final authorizationHeader = body['headers']['Authorization'] ?? body['headers']['authorization'];
  expect(authorizationHeader[0], startsWith('NTLM '));
  expect(body['user'], endsWith(username));
  for (final segment in bodySegments) {
    expect(body['body'], contains(segment));
  }
}
