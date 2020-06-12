import 'dart:io' show Platform;
import 'package:test/test.dart';
import 'package:http/http.dart' as http;
import 'package:ntlm/ntlm.dart';

void main() {
  var username = Platform.environment['NTLM_TEST_USERNAME'];
  var password = Platform.environment['NTLM_TEST_PASSWORD'];
  var url = Platform.environment['NTLM_TEST_URL'];
  var multipartUrl = Platform.environment['NTLM_TEST_MULTIPART_URL'];

  var client = NTLMClient(
    domain: '',
    workstation: '',
    username: username,
    //password: password,
    lmPassword: lmHash(password),
    ntPassword: ntHash(password),
  );

  test('NTLMClient.get() authenticates the request', () async {
    var res = await client.get(url);
    print('Body: ${res.body} Headers: ${res.headers}');

    expect(res.statusCode, 200);
  });

  test('NTLMClient.multipart() authenticates the request', () async {
    var request = http.MultipartRequest('POST', Uri.parse(multipartUrl))
      ..fields['data'] = 'Test Data';
    var res = await client.multipart(request);
    print('Headers: ${res.headers}');

    expect(res.statusCode, 200);
  });
}
