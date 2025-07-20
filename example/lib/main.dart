import 'dart:async';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:flutter/material.dart';
import 'package:native_argon2/native_argon2.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  final nativeArgon2 = NativeArgon2();
  late int sumResult;
  late Future<int> sumAsyncResult;

  @override
  void initState() {
    super.initState();
    sumResult = nativeArgon2.sum(1, 2);
    sumAsyncResult = nativeArgon2.sumAsync(3, 4);

    final password = Uint8List.fromList('password'.codeUnits);
    final salt = Uint8List.fromList('somesalt'.codeUnits);

    final int tCost = 2;
    final int mCost = 65536;
    final int parallelism = 4;
    final int hashLen = 24;
    final int encodedLen = 128; // Must be large enough for encoded output

    // Allocate buffer for the encoded output
    final Pointer<Char> encodedPtr = malloc.allocate<Char>(encodedLen);

    try {
      // // Call your wrapper function
      // final result = argon2iHashEncoded(
      //   tCost: tCost,
      //   mCost: mCost,
      //   parallelism: parallelism,
      //   password: password,
      //   salt: salt,
      //   hashLen: hashLen,
      //   encoded: encodedPtr,
      //   encodedLen: encodedLen,
      // );

      // if (result == 0) {
      //   // Success! Read result as Dart string
      //   final encodedStr = encodedPtr.cast<Utf8>().toDartString();
      //   print('Encoded Argon2 Hash: $encodedStr');
      // } else {
      //   print('Argon2 failed with error code: $result');
      // }
    } finally {
      malloc.free(encodedPtr);
    }
  }

  @override
  Widget build(BuildContext context) {
    const textStyle = TextStyle(fontSize: 25);
    const spacerSmall = SizedBox(height: 10);
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('Native Packages')),
        body: SingleChildScrollView(
          child: Container(
            padding: const EdgeInsets.all(10),
            child: Column(
              children: [
                const Text(
                  'This calls a native function through FFI that is shipped as source in the package. '
                  'The native code is built as part of the Flutter Runner build.',
                  style: textStyle,
                  textAlign: TextAlign.center,
                ),
                spacerSmall,
                Text(
                  'sum(1, 2) = $sumResult',
                  style: textStyle,
                  textAlign: TextAlign.center,
                ),
                spacerSmall,
                FutureBuilder<int>(
                  future: sumAsyncResult,
                  builder: (BuildContext context, AsyncSnapshot<int> value) {
                    final displayValue = (value.hasData)
                        ? value.data
                        : 'loading';
                    return Text(
                      'await sumAsync(3, 4) = $displayValue',
                      style: textStyle,
                      textAlign: TextAlign.center,
                    );
                  },
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
