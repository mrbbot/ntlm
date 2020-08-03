import 'dart:convert';
import 'dart:typed_data';
import 'package:ntlm/src/messages/common/flags.dart' as flags;
import 'package:ntlm/src/messages/common/prefixes.dart';
import 'package:ntlm/src/messages/common/utils.dart';

/// Creates a type 1 NTLM message from the [domain] and [workstation]
String createType1Message({
  String domain = '',
  String workstation = '',
  String headerPrefix = kHeaderPrefixNTLM,
}) {
  domain = domain.toUpperCase();
  workstation = workstation.toUpperCase();
  const signature = 'NTLMSSP\x00';

  const BODY_LENGTH = 40;

  var type1Flags = flags.NTLM_TYPE1_FLAGS;
  if (domain == '') {
    type1Flags -= flags.NTLM_NegotiateOemDomainSupplied;
  }
  if (workstation == '') {
    type1Flags -= flags.NTLM_NegotiateOemWorkstationSupplied;
  }

  var pos = 0;
  var buf = ByteData(BODY_LENGTH + domain.length + workstation.length);

  // protocol
  write(buf, ascii.encode(signature), pos, signature.length);
  pos += signature.length;
  // type 1
  buf.setUint32(pos, 1, Endian.little);
  pos += 4;
  // TYPE1 flag
  buf.setUint32(pos, type1Flags, Endian.little);
  pos += 4;

  // domain length
  buf.setUint16(pos, domain.length, Endian.little);
  pos += 2;
  // domain max length
  buf.setUint16(pos, domain.length, Endian.little);
  pos += 2;
  // domain buffer offset
  var domainOffset = domain == '' ? 0 : BODY_LENGTH + workstation.length;
  buf.setUint32(pos, domainOffset, Endian.little);
  pos += 4;

  // workstation length
  buf.setUint16(pos, workstation.length, Endian.little);
  pos += 2;
  // workstation max length
  buf.setUint16(pos, workstation.length, Endian.little);
  pos += 2;
  // workstation buffer offset
  var workstationOffset = workstation == '' ? 0 : BODY_LENGTH;
  buf.setUint32(pos, workstationOffset, Endian.little);
  pos += 4;

  // ProductMajorVersion
  buf.setUint8(pos, 5);
  pos += 1;
  // ProductMinorVersion
  buf.setUint8(pos, 1);
  pos += 1;
  // ProductBuild
  buf.setUint16(pos, 2600, Endian.little);

  // VersionReserved1
  buf.setUint8(pos, 0);
  pos += 1;
  // VersionReserved2
  buf.setUint8(pos, 0);
  pos += 1;
  // VersionReserved3
  buf.setUint8(pos, 0);
  pos += 1;
  // NTLMRevisionCurrent
  buf.setUint8(pos, 15);
  pos += 1;

  // workstation string
  write(buf, ascii.encode(workstation), pos, workstation.length);
  pos += workstation.length;
  // domain string
  write(buf, ascii.encode(domain), pos, domain.length);
  pos += domain.length;

  return '$headerPrefix ${base64Encode(buf.buffer.asUint8List())}';
}
