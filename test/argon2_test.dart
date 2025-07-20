import 'dart:io';

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
}
