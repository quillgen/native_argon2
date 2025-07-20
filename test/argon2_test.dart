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

  group('Argon2 encoded apis', () {
    test('argon2i encoded', () async {
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

      expect(
        encodedStr,
        equals(
          '\$argon2i\$v=19\$m=65536,t=2,p=4\$c29tZXNhbHQ\$RdescudvJCsgt3ub+b+dWRWJTmaaJObG',
        ),
      );
    });

    test('argon2d encoded', () async {
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
      final result = nativeArgon2.argon2dHashEncoded(params);
      expect(result, 0);
      final encodedStr = encodedPtr.cast<Utf8>().toDartString();

      expect(
        encodedStr,
        equals(
          '\$argon2d\$v=19\$m=65536,t=2,p=4\$c29tZXNhbHQ\$7Kn6V2imUuaFkZmKdZLb3nvg91N5Lt7H',
        ),
      );
    });

    test('argon2id encoded', () async {
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
      final result = nativeArgon2.argon2idHashEncoded(params);
      expect(result, 0);
      final encodedStr = encodedPtr.cast<Utf8>().toDartString();

      expect(
        encodedStr,
        equals(
          '\$argon2id\$v=19\$m=65536,t=2,p=4\$c29tZXNhbHQ\$F1jG2CV3/Nr+yRuIsPKw0J9r4s7cJHBU',
        ),
      );
    });
  });

  group('Argon2 encoded apis (async)', () {
    test('argon2i encoded async', () async {
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

    test('argon2d encoded async', () async {
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
      final result = await nativeArgon2.argon2dHashEncodedAsync(params);
      expect(result, 0);
      final encodedStr = encodedPtr.cast<Utf8>().toDartString();
      malloc.free(encodedPtr);
      expect(
        encodedStr,
        equals(
          '\$argon2d\$v=19\$m=65536,t=2,p=4\$c29tZXNhbHQ\$7Kn6V2imUuaFkZmKdZLb3nvg91N5Lt7H',
        ),
      );
    });

    test('argon2id encoded async', () async {
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
      final result = await nativeArgon2.argon2idHashEncodedAsync(params);
      expect(result, 0);
      final encodedStr = encodedPtr.cast<Utf8>().toDartString();
      malloc.free(encodedPtr);
      expect(
        encodedStr,
        equals(
          '\$argon2id\$v=19\$m=65536,t=2,p=4\$c29tZXNhbHQ\$F1jG2CV3/Nr+yRuIsPKw0J9r4s7cJHBU',
        ),
      );
    });
  });
}
