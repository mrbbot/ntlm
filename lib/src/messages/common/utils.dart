import 'dart:convert';
import 'dart:math' as math;
import 'dart:typed_data';
import 'package:utf/utf.dart' as utf;
import 'package:pointycastle/api.dart';
import 'package:pointycastle/digests/md4.dart';
import 'package:pointycastle/digests/md5.dart';
import 'package:pointycastle/block/modes/ecb.dart';
import 'package:ntlm/src/des/des.dart';

void write(ByteData buf, Uint8List data, int offset, int length) {
  for (var i = 0; i < length; i++) {
    buf.setUint8(i + offset, data[i]);
  }
}

void _arrayCopy(List src, int srcPos, List dest, int destPos, int length) {
  for (var i = 0; i < length; i++) {
    dest[i + destPos] = src[i + srcPos];
  }
}

void _oddParity(List<int> bytes) {
  for (var i = 0; i < bytes.length; i++) {
    var b = bytes[i];

    var needsParity = (((b >> 7) ^
                (b >> 6) ^
                (b >> 5) ^
                (b >> 4) ^
                (b >> 3) ^
                (b >> 2) ^
                (b >> 1)) &
            0x01) ==
        0;

    if (needsParity) {
      bytes[i] |= 0x01;
    } else {
      bytes[i] &= 0xfe;
    }
  }
}

KeyParameter _createDESKey(List<int> bytes, int offset) {
  var uint8Bytes = Uint8List.fromList(bytes);
  var keyBytes = List<int>.generate(7, (i) => uint8Bytes[i + offset]);
  var material = List<int>(8);
  material[0] = keyBytes[0].toSigned(8);
  material[1] = (keyBytes[0] << 7 | (keyBytes[1] & 0xff) >> 1).toSigned(8);
  material[2] = (keyBytes[1] << 6 | (keyBytes[2] & 0xff) >> 2).toSigned(8);
  material[3] = (keyBytes[2] << 5 | (keyBytes[3] & 0xff) >> 3).toSigned(8);
  material[4] = (keyBytes[3] << 4 | (keyBytes[4] & 0xff) >> 4).toSigned(8);
  material[5] = (keyBytes[4] << 3 | (keyBytes[5] & 0xff) >> 5).toSigned(8);
  material[6] = (keyBytes[5] << 2 | (keyBytes[6] & 0xff) >> 6).toSigned(8);
  material[7] = (keyBytes[6] << 1).toSigned(8);
  _oddParity(material);
  return KeyParameter(
    Uint8List.fromList(material.map((v) => v.toUnsigned(8)).toList()),
  );
}

Uint8List createLMHashedPasswordV1(String password) {
  var oemPassword = ascii.encode(password.toUpperCase());
  var length = math.min(oemPassword.length, 14);
  var keyBytes = List<int>.filled(14, 0);
  _arrayCopy(oemPassword, 0, keyBytes, 0, length);
  var lowKey = _createDESKey(keyBytes, 0);
  var highKey = _createDESKey(keyBytes, 7);
  var magic = ascii.encode('KGS!@#\$%');
  BlockCipher des = ECBBlockCipher(DESEngine());
  des.init(true, lowKey);
  var lowHash = des.process(magic).map((v) => v.toSigned(8)).toList();
  des.init(true, highKey);
  var highHash = des.process(magic).map((v) => v.toSigned(8)).toList();
  var lmHash = Uint8List(16);
  _arrayCopy(lowHash, 0, lmHash, 0, 8);
  _arrayCopy(highHash, 0, lmHash, 8, 8);
  return lmHash;
}

Uint8List createNTHashedPasswordV1(String password) {
  var unicodePassword = utf.encodeUtf16le(password);
  Digest md4 = MD4Digest();
  return md4.process(Uint8List.fromList(unicodePassword));
}

Uint8List calculateResponse(Uint8List hash, Uint8List challenge) {
  var keyBytes = List.filled(21, 0);
  _arrayCopy(hash, 0, keyBytes, 0, 16);
  var lowKey = _createDESKey(keyBytes, 0);
  var middleKey = _createDESKey(keyBytes, 7);
  var highKey = _createDESKey(keyBytes, 14);
  BlockCipher des = ECBBlockCipher(DESEngine());
  var uint8Challenge = Uint8List.fromList(challenge);
  des.init(true, lowKey);
  var lowResponse =
      des.process(uint8Challenge).map((v) => v.toSigned(8)).toList();
  des.init(true, middleKey);
  var middleResponse =
      des.process(uint8Challenge).map((v) => v.toSigned(8)).toList();
  des.init(true, highKey);
  var highResponse =
      des.process(uint8Challenge).map((v) => v.toSigned(8)).toList();
  var lmResponse = Uint8List.fromList(List.filled(24, 0));
  _arrayCopy(lowResponse, 0, lmResponse, 0, 8);
  _arrayCopy(middleResponse, 0, lmResponse, 8, 8);
  _arrayCopy(highResponse, 0, lmResponse, 16, 8);
  return lmResponse;
}

Map<String, Uint8List> calculateNTLM2Response(Uint8List responseKeyNT,
    Uint8List serverChallenge, Uint8List clientChallenge) {
  var lmChallengeResponse =
      Uint8List.fromList(List.filled(clientChallenge.length + 16, 0));
  _arrayCopy(
      clientChallenge, 0, lmChallengeResponse, 0, clientChallenge.length);

  var buf = Uint8List.fromList(
      List.filled(serverChallenge.length + clientChallenge.length, 0));
  _arrayCopy(serverChallenge, 0, buf, 0, serverChallenge.length);
  _arrayCopy(
      clientChallenge, 0, buf, serverChallenge.length, clientChallenge.length);
  var md5 = MD5Digest();
  var session = md5.process(buf);
  var ntChallengeResponse = calculateResponse(
      responseKeyNT, Uint8List.fromList(session.sublist(0, 8)));

  return {
    'LM': lmChallengeResponse,
    'NT': ntChallengeResponse,
  };
}

math.Random _random = math.Random();

Uint8List createRandomNonce([int length = 8]) =>
    Uint8List.fromList(List.generate(length, (i) => _random.nextInt(255)));
