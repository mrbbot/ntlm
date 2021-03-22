import 'dart:convert';
import 'dart:typed_data';
import 'package:ntlm/src/messages/common/flags.dart' as flags;
import 'package:ntlm/src/messages/common/prefixes.dart';
import 'package:ntlm/src/messages/common/utils.dart';
import 'package:ntlm/src/messages/type2.dart';

/// Creates a type 3 NTLM message based on the response in [msg2].
String createType3Message(
  Type2Message msg2, {
  String domain = '',
  String workstation = '',
  required String username,
  String? password,
  String? lmPassword,
  String? ntPassword,
  String headerPrefix = kHeaderPrefixNTLM,
}) {
  if (password == null && (lmPassword == null || ntPassword == null)) {
    throw ArgumentError(
      'You must provide a password or the LM and NT hash of a password.',
    );
  }

  var serverNonce = msg2.serverChallenge;
  var negotiateFlags = msg2.negotiateFlags;

  var isUnicode = negotiateFlags & flags.NTLM_NegotiateUnicode != 0;
  var isNegotiateExtendedSecurity =
      negotiateFlags & flags.NTLM_NegotiateExtendedSecurity != 0;

  const BODY_LENGTH = 72;

  domain = domain.toUpperCase();
  workstation = workstation.toUpperCase();
  var encryptedRandomSessionKey = '';

  var encode =
      (String str) => isUnicode ? encodeUtf16le(str) : ascii.encode(str);
  var workstationBytes = encode(workstation);
  var domainBytes = encode(domain);
  var usernameBytes = encode(username);
  var encryptedRandomSessionKeyBytes = encode(encryptedRandomSessionKey);

  var lmChallengeResponse = calculateResponse(
      lmPassword != null
          ? base64Decode(lmPassword)
          : createLMHashedPasswordV1(password!),
      serverNonce);
  var ntChallengeResponse = calculateResponse(
      ntPassword != null
          ? base64Decode(ntPassword)
          : createNTHashedPasswordV1(password!),
      serverNonce);
  if (isNegotiateExtendedSecurity) {
    var passwordHash = ntPassword != null
        ? base64Decode(ntPassword)
        : createNTHashedPasswordV1(password!);
    var clientNonce = createRandomNonce();

    lmChallengeResponse = calculateLMResponseV2(
        msg2.serverChallenge, username, passwordHash, clientNonce);
    ntChallengeResponse =
        calculateNTLMResponseV2(msg2, username, passwordHash, clientNonce);
  }

  const signature = 'NTLMSSP\x00';

  var pos = 0;
  var buf = ByteData(
    BODY_LENGTH +
        domainBytes.length +
        usernameBytes.length +
        workstationBytes.length +
        lmChallengeResponse.length +
        ntChallengeResponse.length +
        encryptedRandomSessionKeyBytes.length,
  );

  // protocol
  write(buf, ascii.encode(signature), pos, signature.length);
  pos += signature.length;
  // type 3
  buf.setUint32(pos, 3, Endian.little);
  pos += 4;

  // LmChallengeResponseLen
  buf.setUint16(pos, lmChallengeResponse.length, Endian.little);
  pos += 2;
  // LmChallengeResponseMaxLen
  buf.setUint16(pos, lmChallengeResponse.length, Endian.little);
  pos += 2;
  // LmChallengeResponseOffset
  buf.setUint32(
      pos,
      BODY_LENGTH +
          domainBytes.length +
          usernameBytes.length +
          workstationBytes.length,
      Endian.little);
  pos += 4;

  // NtChallengeResponseLen
  buf.setUint16(pos, ntChallengeResponse.length, Endian.little);
  pos += 2;
  // NtChallengeResponseMaxLen
  buf.setUint16(pos, ntChallengeResponse.length, Endian.little);
  pos += 2;
  // NtChallengeResponseOffset
  buf.setUint32(
      pos,
      BODY_LENGTH +
          domainBytes.length +
          usernameBytes.length +
          workstationBytes.length +
          lmChallengeResponse.length,
      Endian.little);
  pos += 4;

  // DomainNameLen
  buf.setUint16(pos, domainBytes.length, Endian.little);
  pos += 2;
  // DomainNameMaxLen
  buf.setUint16(pos, domainBytes.length, Endian.little);
  pos += 2;
  // DomainNameOffset
  buf.setUint32(pos, BODY_LENGTH, Endian.little);
  pos += 4;

  // UserNameLen
  buf.setUint16(pos, usernameBytes.length, Endian.little);
  pos += 2;
  // UserNameMaxLen
  buf.setUint16(pos, usernameBytes.length, Endian.little);
  pos += 2;
  // UserNameOffset
  buf.setUint32(pos, BODY_LENGTH + domainBytes.length, Endian.little);
  pos += 4;

  // WorkstationLen
  buf.setUint16(pos, workstationBytes.length, Endian.little);
  pos += 2;
  // WorkstationMaxLen
  buf.setUint16(pos, workstationBytes.length, Endian.little);
  pos += 2;
  // WorkstationOffset
  buf.setUint32(pos, BODY_LENGTH + domainBytes.length + usernameBytes.length,
      Endian.little);
  pos += 4;

  // EncryptedRandomSessionKeyLen
  buf.setUint16(pos, encryptedRandomSessionKeyBytes.length, Endian.little);
  pos += 2;
  // EncryptedRandomSessionKeyMaxLen
  buf.setUint16(pos, encryptedRandomSessionKeyBytes.length, Endian.little);
  pos += 2;
  // EncryptedRandomSessionKeyOffset
  buf.setUint32(
      pos,
      BODY_LENGTH +
          domainBytes.length +
          usernameBytes.length +
          workstationBytes.length +
          lmChallengeResponse.length +
          ntChallengeResponse.length,
      Endian.little);
  pos += 4;

  // NegotiateFlags
  buf.setUint32(pos, flags.NTLM_TYPE2_FLAGS, Endian.little);
  pos += 4;

  // ProductMajorVersion
  buf.setUint8(pos, 5);
  pos++;
  // ProductMinorVersion
  buf.setUint8(pos, 1);
  pos++;
  // ProductBuild
  buf.setUint16(pos, 2600, Endian.little);
  pos += 2;
  // VersionReserved1
  buf.setUint8(pos, 0);
  pos++;
  // VersionReserved2
  buf.setUint8(pos, 0);
  pos++;
  // VersionReserved3
  buf.setUint8(pos, 0);
  pos++;
  // NTLMRevisionCurrent
  buf.setUint8(pos, 15);
  pos++;

  write(buf, domainBytes, pos, domainBytes.length);
  pos += domainBytes.length;
  write(buf, usernameBytes, pos, usernameBytes.length);
  pos += usernameBytes.length;
  write(buf, workstationBytes, pos, workstationBytes.length);
  pos += workstationBytes.length;
  write(buf, lmChallengeResponse, pos, lmChallengeResponse.length);
  pos += lmChallengeResponse.length;
  write(buf, ntChallengeResponse, pos, ntChallengeResponse.length);
  pos += ntChallengeResponse.length;
  write(buf, encryptedRandomSessionKeyBytes, pos,
      encryptedRandomSessionKeyBytes.length);
  pos += encryptedRandomSessionKeyBytes.length;

  return '$headerPrefix ${base64Encode(buf.buffer.asUint8List())}';
}
