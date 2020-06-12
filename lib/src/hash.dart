import 'dart:convert';
import 'dart:typed_data';
import 'package:ntlm/src/messages/common/utils.dart';

/// Generates a base 64 string from a list of integers.
String _encode(Uint8List hash) => base64Encode(List.from(hash));

/// Generates the base 64 lan manager hash corresponding to the [password].
String lmHash(String password) => _encode(createLMHashedPasswordV1(password));

/// Generates the base 64 NT hash corresponding to the [password].
String ntHash(String password) => _encode(createNTHashedPasswordV1(password));
