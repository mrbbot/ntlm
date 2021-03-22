import 'dart:convert';
import 'dart:typed_data';
import 'package:ntlm/src/messages/common/flags.dart' as flags;
import 'package:ntlm/src/messages/common/prefixes.dart';

/// Data class for all information contained in the type 2 response.
///
/// Used to calculate the type 3 response.
class Type2Message {
  final Uint8List signature;
  final int type;
  final int targetNameLength;
  final int targetNameMaxLength;
  final int targetNameOffset;
  final Uint8List targetName;
  final int negotiateFlags;
  final Uint8List serverChallenge;
  final Uint8List reserved;
  final int? targetInfoLength;
  final int? targetInfoMaxLength;
  final int? targetInfoOffset;
  final Uint8List? targetInfo;

  const Type2Message({
    required this.signature,
    required this.type,
    required this.targetNameLength,
    required this.targetNameMaxLength,
    required this.targetNameOffset,
    required this.targetName,
    required this.negotiateFlags,
    required this.serverChallenge,
    required this.reserved,
    this.targetInfoLength,
    this.targetInfoMaxLength,
    this.targetInfoOffset,
    this.targetInfo,
  });

  @override
  String toString() {
    return '---BEGIN TYPE 2 MESSAGE---\n'
        'Signature:        ${ascii.decode(signature.toList(), allowInvalid: true)}\n'
        '  Raw:            ${signature.toList()}\n'
        'Type:             $type\n'
        'Target Name:      ${ascii.decode(targetName.toList(), allowInvalid: true)}\n'
        '  Length:         $targetNameLength\n'
        '  Max Length:     $targetNameMaxLength\n'
        '  Offset:         $targetNameOffset\n'
        '  Raw:            ${targetName.toList()}\n'
        'Negotiate Flags:  $negotiateFlags\n'
        'Server Challenge: ${serverChallenge.toList()}\n'
        'Reserved:         ${reserved.toList()}\n'
        'Target Info:      ${targetInfo == null ? null : ascii.decode(targetInfo!.toList(), allowInvalid: true)}\n'
        '  Length:         $targetInfoLength\n'
        '  Max Length:     $targetInfoMaxLength\n'
        '  Offset:         $targetInfoOffset\n'
        '  Raw:            ${targetInfo?.toList()}\n'
        '---END TYPE 2 MESSAGE---';
  }
}

/// Extract the information from the type 2 [rawMsg] into an object.
Type2Message parseType2Message(
  String rawMsg, {
  String headerPrefix = kHeaderPrefixNTLM,
}) {
  if (rawMsg.startsWith('$headerPrefix ')) {
    rawMsg = rawMsg.substring('$headerPrefix '.length);
  }

  final buf = base64Decode(rawMsg).buffer;
  final bufView = ByteData.view(buf);

  final signature = buf.asUint8List(0, 8);
  final type = bufView.getInt16(8, Endian.little);

  if (type != 2) {
    throw ArgumentError('A type 2 response was not passed!');
  }

  final targetNameLength = bufView.getInt16(12, Endian.little);
  final targetNameMaxLength = bufView.getInt16(14, Endian.little);
  final targetNameOffset = bufView.getInt32(16, Endian.little);
  final targetName = buf.asUint8List(targetNameOffset, targetNameLength);

  final negotiateFlags = bufView.getInt32(20, Endian.little);
  final serverChallenge = buf.asUint8List(24, 8);
  final reserved = buf.asUint8List(32, 8);

  int? targetInfoLength;
  int? targetInfoMaxLength;
  int? targetInfoOffset;
  Uint8List? targetInfo;
  if (negotiateFlags & flags.NTLM_NegotiateTargetInfo != 0) {
    targetInfoLength = bufView.getInt16(40, Endian.little);
    targetInfoMaxLength = bufView.getInt16(42, Endian.little);
    targetInfoOffset = bufView.getInt32(44, Endian.little);
    targetInfo = buf.asUint8List(targetInfoOffset, targetInfoLength);
  }

  return Type2Message(
    signature: signature,
    type: type,
    targetNameLength: targetNameLength,
    targetNameMaxLength: targetNameMaxLength,
    targetNameOffset: targetNameOffset,
    targetName: targetName,
    negotiateFlags: negotiateFlags,
    serverChallenge: serverChallenge,
    reserved: reserved,
    targetInfoLength: targetInfoLength,
    targetInfoMaxLength: targetInfoMaxLength,
    targetInfoOffset: targetInfoOffset,
    targetInfo: targetInfo,
  );
}
