import 'dart:typed_data';
import 'dart:convert';
import 'package:utf/utf.dart';
import 'package:ntlm/src/messages/common/utils.dart';
import 'package:ntlm/src/messages/common/flags.dart' as flags;
import 'package:ntlm/src/messages/type2.dart';

/// Creates a type 3 NTLM message based on the response in [msg2].
String createType3Message(
  Type2Message msg2, {
  String domain = "",
  String workstation = "",
  String username,
  String password,
  String lmPassword,
  String ntPassword,
}) {
  if (password == null && (lmPassword == null || ntPassword == null)) {
    throw new ArgumentError(
      "You must provide a password or the LM and NT hash of a password.",
    );
  }

  Uint8List serverNonce = msg2.serverChallenge;
  int negotiateFlags = msg2.negotiateFlags;

  bool isUnicode = negotiateFlags & flags.NTLM_NegotiateUnicode != 0;
  bool isNegotiateExtendedSecurity =
      negotiateFlags & flags.NTLM_NegotiateExtendedSecurity != 0;

  const BODY_LENGTH = 72;

  domain = domain.toUpperCase();
  workstation = workstation.toUpperCase();
  String encryptedRandomSessionKey = "";

  var encode = (String str) => isUnicode
      ? new Uint8List.fromList(encodeUtf16le(str))
      : ascii.encode(str);
  Uint8List workstationBytes = encode(workstation);
  Uint8List domainBytes = encode(domain);
  Uint8List usernameBytes = encode(username);
  Uint8List encryptedRandomSessionKeyBytes = encode(encryptedRandomSessionKey);

  Uint8List lmChallengeResponse = calculateResponse(
      lmPassword != null
          ? base64Decode(lmPassword)
          : createLMHashedPasswordV1(password),
      serverNonce);
  Uint8List ntChallengeResponse = calculateResponse(
      ntPassword != null
          ? base64Decode(ntPassword)
          : createNTHashedPasswordV1(password),
      serverNonce);
  if (isNegotiateExtendedSecurity) {
    Uint8List passwordHash = ntPassword != null
        ? base64Decode(ntPassword)
        : createNTHashedPasswordV1(password);
    Uint8List clientNonce = createRandomNonce();
    Map<String, Uint8List> challenges =
        calculateNTLM2Response(passwordHash, serverNonce, clientNonce);

    lmChallengeResponse = challenges["LM"];
    ntChallengeResponse = challenges["NT"];
  }

  const signature = "NTLMSSP\x00";

  int pos = 0;
  ByteData buf = new ByteData(
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

  return "NTLM ${base64Encode(buf.buffer.asUint8List())}";
}
