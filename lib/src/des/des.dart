import 'dart:typed_data';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/src/impl/base_block_cipher.dart';
import 'package:pointycastle/src/ufixnum.dart';
import 'package:pointycastle/src/registry/registry.dart';
import 'package:fixnum/fixnum.dart';
import 'package:ntlm/src/des/des_constants.dart';

class DESEngine extends BaseBlockCipher {
  static final FactoryConfig FACTORY_CONFIG =
      StaticFactoryConfig(BlockCipher, 'DES', () => DESEngine());

  static const _BLOCK_SIZE = 8;

  List<Int32>? _workingKey;

  @override
  String get algorithmName => 'DES';

  @override
  int get blockSize => _BLOCK_SIZE;

  @override
  void reset() {}

  @override
  void init(bool forEncryption, covariant KeyParameter params) {
    if (params.key.length > 8) {
      throw ArgumentError('DES key too long - should be 8 bytes');
    }

    _workingKey = _generateWorkingKey(forEncryption, params.key);
  }

  @override
  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    if (_workingKey == null) {
      throw StateError('DES engine not initialised');
    }

    if ((inpOff + _BLOCK_SIZE) > inp.length) {
      throw ArgumentError('input buffer too short');
    }

    if ((outOff + _BLOCK_SIZE) > out.length) {
      throw ArgumentError('output buffer too short');
    }

    _desFunc(_workingKey!, inp, inpOff, out, outOff);

    return _BLOCK_SIZE;
  }

  List<Int32> _generateWorkingKey(bool encrypting, Uint8List key) {
    var newKey = List<Int32>.filled(32, Int32.ZERO);
    var pc1m = List<bool>.filled(56, false);
    var pcr = List<bool>.filled(56, false);

    for (var j = 0; j < 56; j++) {
      var l = pc1[j];

      pc1m[j] =
          ((key[l.shiftRightUnsigned(3).toInt()] & bytebit[(l & 7).toInt()]) !=
              0);
    }

    for (IntX i = Int32.ZERO; i < 16; i++) {
      IntX l, m, n;

      if (encrypting) {
        m = i << 1;
      } else {
        m = (Int32(15) - i) << 1;
      }

      n = m + 1 as Int32;
      newKey[m.toInt()] = Int32.ZERO;
      newKey[n.toInt()] = Int32.ZERO;

      for (IntX j = Int32.ZERO; j < 28; j++) {
        l = j + totrot[i.toInt()];
        if (l < 28) {
          pcr[j.toInt()] = pc1m[l.toInt()];
        } else {
          pcr[j.toInt()] = pc1m[(l - 28).toInt()];
        }
      }

      for (IntX j = Int32(28); j < 56; j++) {
        l = j + totrot[i.toInt()];
        if (l < 56) {
          pcr[j.toInt()] = pc1m[l.toInt()];
        } else {
          pcr[j.toInt()] = pc1m[(l - 28).toInt()];
        }
      }

      for (IntX j = Int32.ZERO; j < 24; j++) {
        if (pcr[pc2[j.toInt()].toInt()]) {
          newKey[m.toInt()] |= bigbyte[j.toInt()];
        }

        if (pcr[pc2[(j + 24).toInt()].toInt()]) {
          newKey[n.toInt()] |= bigbyte[j.toInt()];
        }
      }
    }

    //
    // store the processed key
    //
    for (var i = 0; i != 32; i += 2) {
      Int32 i1, i2;

      i1 = newKey[i];
      i2 = newKey[i + 1];

      newKey[i] = ((i1 & 0x00fc0000) << 6) |
          ((i1 & 0x00000fc0) << 10) |
          ((i2 & 0x00fc0000).shiftRightUnsigned(10)) |
          ((i2 & 0x00000fc0).shiftRightUnsigned(6));

      newKey[i + 1] = ((i1 & 0x0003f000) << 12) |
          ((i1 & 0x0000003f) << 16) |
          ((i2 & 0x0003f000).shiftRightUnsigned(4)) |
          (i2 & 0x0000003f);
    }

    return newKey;
  }

  void _desFunc(
      List<Int32> wKey, Uint8List inp, int inOff, Uint8List out, int outOff) {
    Int32 work, right, left;

    left = Int32(unpack32(inp, inOff, Endian.big));
    right = Int32(unpack32(inp, inOff + 4, Endian.big));

    work = ((left.shiftRightUnsigned(4)) ^ right) & 0x0f0f0f0f;
    right ^= work;
    left ^= (work << 4);
    work = ((left.shiftRightUnsigned(16)) ^ right) & 0x0000ffff;
    right ^= work;
    left ^= (work << 16);
    work = ((right.shiftRightUnsigned(2)) ^ left) & 0x33333333;
    left ^= work;
    right ^= (work << 2);
    work = ((right.shiftRightUnsigned(8)) ^ left) & 0x00ff00ff;
    left ^= work;
    right ^= (work << 8);
    right = (right << 1) | (right.shiftRightUnsigned(31));
    work = (left ^ right) & 0xaaaaaaaa;
    left ^= work;
    right ^= work;
    left = (left << 1) | (left.shiftRightUnsigned(31));

    for (var round = 0; round < 8; round++) {
      Int32 fval;

      work = (right << 28) | (right.shiftRightUnsigned(4));
      work ^= wKey[round * 4 + 0];

      fval = SP7[(work & 0x3f).toInt()];
      fval |= SP5[((work.shiftRightUnsigned(8)) & 0x3f).toInt()];
      fval |= SP3[((work.shiftRightUnsigned(16)) & 0x3f).toInt()];
      fval |= SP1[((work.shiftRightUnsigned(24)) & 0x3f).toInt()];
      work = right ^ wKey[(round * 4 + 1)];
      fval |= SP8[(work & 0x3f).toInt()];
      fval |= SP6[((work.shiftRightUnsigned(8)) & 0x3f).toInt()];
      fval |= SP4[((work.shiftRightUnsigned(16)) & 0x3f).toInt()];
      fval |= SP2[((work.shiftRightUnsigned(24)) & 0x3f).toInt()];
      left ^= fval;
      work = (left << 28) | (left.shiftRightUnsigned(4));
      work ^= wKey[(round * 4 + 2)];
      fval = SP7[(work & 0x3f).toInt()];
      fval |= SP5[((work.shiftRightUnsigned(8)) & 0x3f).toInt()];
      fval |= SP3[((work.shiftRightUnsigned(16)) & 0x3f).toInt()];
      fval |= SP1[((work.shiftRightUnsigned(24)) & 0x3f).toInt()];
      work = left ^ wKey[(round * 4 + 3)];
      fval |= SP8[(work & 0x3f).toInt()];
      fval |= SP6[((work.shiftRightUnsigned(8)) & 0x3f).toInt()];
      fval |= SP4[((work.shiftRightUnsigned(16)) & 0x3f).toInt()];
      fval |= SP2[((work.shiftRightUnsigned(24)) & 0x3f).toInt()];
      right ^= fval;
    }

    right = (right << 31) | (right.shiftRightUnsigned(1));
    work = (left ^ right) & 0xaaaaaaaa;
    left ^= work;
    right ^= work;
    left = (left << 31) | (left.shiftRightUnsigned(1));
    work = ((left.shiftRightUnsigned(8)) ^ right) & 0x00ff00ff;
    right ^= work;
    left ^= (work << 8);
    work = ((left.shiftRightUnsigned(2)) ^ right) & 0x33333333;
    right ^= work;
    left ^= (work << 2);
    work = ((right.shiftRightUnsigned(16)) ^ left) & 0x0000ffff;
    left ^= work;
    right ^= (work << 16);
    work = ((right.shiftRightUnsigned(4)) ^ left) & 0x0f0f0f0f;
    left ^= work;
    right ^= (work << 4);

    pack32(right.toInt().toUnsigned(32), out, outOff, Endian.big);
    pack32(left.toInt().toUnsigned(32), out, outOff + 4, Endian.big);
  }
}
