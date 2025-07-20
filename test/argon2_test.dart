import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:native_argon2/native_argon2.dart';
import 'package:test/test.dart';

void main() {
  group('Test', () {
    final DynamicLibrary dylib;
    if (Platform.isMacOS) {
      dylib = DynamicLibrary.open('src/build/libnative_argon2.dylib');
    } else {
      dylib = DynamicLibrary.open('src/build/libnative_argon2.so');
    }
    test('hashPasswordString returns a valid encoded hash', () async {
      final argon2 = NativeArgon2(overrideDylib: dylib);

      final int encodedLen = 128;
      final Pointer<Char> encodedPtr = malloc.allocate<Char>(encodedLen);
      int result = argon2.argon2iHashEncoded(
        tCost: 2,
        mCost: 65535,
        parallelism: 4,
        password: Uint8List.fromList('password'.codeUnits),
        salt: Uint8List.fromList('somesalt'.codeUnits),
        hashLen: 24,
        encoded: encodedPtr,
        encodedLen: encodedLen,
      );
      malloc.free(encodedPtr);

      expect(result, equals(0));
    });
  });
}
