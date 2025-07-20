import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:native_argon2/native_argon2.dart';
import 'package:test/test.dart';

void main() {
  setUp(() {
    String testLibPath;

    if (Platform.isMacOS) {
      testLibPath = 'src/build/libnative_argon2.dylib';
    } else if (Platform.isLinux) {
      testLibPath = 'src/build/libnative_argon2.so';
    } else if (Platform.isWindows) {
      testLibPath = 'src/build/libnative_argon2.dll';
    } else {
      throw UnsupportedError(
        'Tests on ${Platform.operatingSystem} not supported',
      );
    }
    Argon2LibraryLoader.instance.configure(libraryPath: testLibPath);
  });

  test('sum function works with injected library', () {
    final nativeArgon2 = NativeArgon2();
    expect(nativeArgon2.sum(3, 4), 7);
  });

  test('sumAsync works with isolates using injected library', () async {
    final nativeArgon2 = NativeArgon2();
    final result = await nativeArgon2.sumAsync(5, 7);
    expect(result, 12);
  });

  group('Argon2i wrapped high-level api', () {
    test('argon2i returns a valid encoded hash', () async {
      final nativeArgon2 = NativeArgon2();
      final int encodedLen = 128;
      final Pointer<Char> encodedPtr = malloc.allocate<Char>(encodedLen);
      final params = Argon2EncodedParams(
        tCost: 2,
        mCost: 65536,
        parallelism: 4,
        password: utf8.encode('password'),
        salt: utf8.encode('somesalt'),
        hashLen: 24,
        encoded: encodedPtr,
        encodedLen: encodedLen,
      );
      final result = nativeArgon2.argon2iHashEncoded(params);
      expect(result, 0);
      final encodedStr = encodedPtr.cast<Utf8>().toDartString();
      malloc.free(encodedPtr);
      expect(
        encodedStr,
        equals(
          '\$argon2i\$v=19\$m=65536,t=2,p=4\$c29tZXNhbHQ\$RdescudvJCsgt3ub+b+dWRWJTmaaJObG',
        ),
      );
    });
  });

  group('Argon2i async high-level api', () {
    test('argon2i returns a valid encoded hash', () async {
      final nativeArgon2 = NativeArgon2();
      final int encodedLen = 128;
      final Pointer<Char> encodedPtr = malloc.allocate<Char>(encodedLen);
      final params = Argon2EncodedParams(
        tCost: 2,
        mCost: 65536,
        parallelism: 4,
        password: utf8.encode('password'),
        salt: utf8.encode('somesalt'),
        hashLen: 24,
        encoded: encodedPtr,
        encodedLen: encodedLen,
      );
      final result = await nativeArgon2.argon2iHashEncodedAsync(params);
      expect(result, 0);
      final encodedStr = encodedPtr.cast<Utf8>().toDartString();
      malloc.free(encodedPtr);
      expect(
        encodedStr,
        equals(
          '\$argon2i\$v=19\$m=65536,t=2,p=4\$c29tZXNhbHQ\$RdescudvJCsgt3ub+b+dWRWJTmaaJObG',
        ),
      );
    });
  });
}
