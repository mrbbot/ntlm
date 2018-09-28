import 'package:ntlm/src/messages/common/utils.dart';
import 'dart:convert';
import 'dart:typed_data';

String _encode(Uint8List hash) => base64Encode(new List.from(hash));

String lmHash(String password) => _encode(createLMHashedPasswordV1(password));

String ntHash(String password) => _encode(createNTHashedPasswordV1(password));
