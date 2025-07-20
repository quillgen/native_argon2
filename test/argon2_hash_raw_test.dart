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

  group('Argon2 raw apis', () {
    test('argon2i raw', () async {
      final nativeArgon2 = NativeArgon2();
      final int hashLen = 24;
      final Pointer<Uint8> hashStr = malloc.allocate<Uint8>(hashLen);
      final params = Argon2RawParams(
        tCost: 2,
        mCost: 65536,
        parallelism: 4,
        password: utf8.encode('password'),
        salt: utf8.encode('somesalt'),
        hashLen: 24,
        hash: hashStr.cast<Void>(),
      );
      final result = nativeArgon2.argon2iHashRaw(params);
      expect(result, 0);
      final uint8list = hashStr.cast<Uint8>().asTypedList(hashLen);
      final encodedStr = base64.encode(uint8list);
      malloc.free(hashStr);

      expect(encodedStr, equals('RdescudvJCsgt3ub+b+dWRWJTmaaJObG'));
    });

    test('argon2d raw', () async {
      final nativeArgon2 = NativeArgon2();
      final int hashLen = 24;
      final Pointer<Uint8> hashStr = malloc.allocate<Uint8>(hashLen);
      final params = Argon2RawParams(
        tCost: 2,
        mCost: 65536,
        parallelism: 4,
        password: utf8.encode('password'),
        salt: utf8.encode('somesalt'),
        hashLen: 24,
        hash: hashStr.cast<Void>(),
      );
      final result = nativeArgon2.argon2dHashRaw(params);
      expect(result, 0);
      final uint8list = hashStr.cast<Uint8>().asTypedList(hashLen);
      final encodedStr = base64.encode(uint8list);
      malloc.free(hashStr);
      expect(encodedStr, equals('7Kn6V2imUuaFkZmKdZLb3nvg91N5Lt7H'));
    });

    test('argon2id raw', () async {
      final nativeArgon2 = NativeArgon2();
      final int hashLen = 24;
      final Pointer<Uint8> hashStr = malloc.allocate<Uint8>(hashLen);
      final params = Argon2RawParams(
        tCost: 2,
        mCost: 65536,
        parallelism: 4,
        password: utf8.encode('password'),
        salt: utf8.encode('somesalt'),
        hashLen: 24,
        hash: hashStr.cast<Void>(),
      );
      final result = nativeArgon2.argon2idHashRaw(params);
      expect(result, 0);
      final uint8list = hashStr.cast<Uint8>().asTypedList(hashLen);
      final encodedStr = base64.encode(uint8list);
      malloc.free(hashStr);
      expect(encodedStr, equals('F1jG2CV3/Nr+yRuIsPKw0J9r4s7cJHBU'));
    });
  });

  group('Argon2 raw apis (async)', () {
    test('argon2i raw async', () async {
      final nativeArgon2 = NativeArgon2();
      final int hashLen = 24;
      final Pointer<Uint8> hashStr = malloc.allocate<Uint8>(hashLen);
      final params = Argon2RawParams(
        tCost: 2,
        mCost: 65536,
        parallelism: 4,
        password: utf8.encode('password'),
        salt: utf8.encode('somesalt'),
        hashLen: 24,
        hash: hashStr.cast<Void>(),
      );
      final result = await nativeArgon2.argon2iHashRawAsync(params);
      expect(result, 0);
      final uint8list = hashStr.cast<Uint8>().asTypedList(hashLen);
      final encodedStr = base64.encode(uint8list);
      malloc.free(hashStr);
      expect(encodedStr, equals('RdescudvJCsgt3ub+b+dWRWJTmaaJObG'));
    });

    test('argon2d raw async', () async {
      final nativeArgon2 = NativeArgon2();
      final int hashLen = 24;
      final Pointer<Uint8> hashStr = malloc.allocate<Uint8>(hashLen);
      final params = Argon2RawParams(
        tCost: 2,
        mCost: 65536,
        parallelism: 4,
        password: utf8.encode('password'),
        salt: utf8.encode('somesalt'),
        hashLen: 24,
        hash: hashStr.cast<Void>(),
      );
      final result = await nativeArgon2.argon2dHashRawAsync(params);
      expect(result, 0);
      final uint8list = hashStr.cast<Uint8>().asTypedList(hashLen);
      final encodedStr = base64.encode(uint8list);
      malloc.free(hashStr);
      expect(encodedStr, equals('7Kn6V2imUuaFkZmKdZLb3nvg91N5Lt7H'));
    });

    test('argon2id raw async', () async {
      final nativeArgon2 = NativeArgon2();
      final int hashLen = 24;
      final Pointer<Uint8> hashStr = malloc.allocate<Uint8>(hashLen);
      final params = Argon2RawParams(
        tCost: 2,
        mCost: 65536,
        parallelism: 4,
        password: utf8.encode('password'),
        salt: utf8.encode('somesalt'),
        hashLen: 24,
        hash: hashStr.cast<Void>(),
      );
      final result = await nativeArgon2.argon2idHashRawAsync(params);
      expect(result, 0);
      final uint8list = hashStr.cast<Uint8>().asTypedList(hashLen);
      final encodedStr = base64.encode(uint8list);
      malloc.free(hashStr);
      expect(encodedStr, equals('F1jG2CV3/Nr+yRuIsPKw0J9r4s7cJHBU'));
    });
  });
}
