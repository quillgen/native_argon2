import 'dart:async';
import 'dart:convert';
import 'dart:ffi';

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
  late Future<String> argon2iAsyncResult;

  Future<String> _argon2i() async {
    final int encodedLen = 128;
    final Pointer<Char> encodedPtr = malloc.allocate<Char>(encodedLen);
    try {
      int result = await nativeArgon2.argon2iHashEncodedAsync(
        Argon2EncodedParams(
          tCost: 2,
          mCost: 1 << 16,
          parallelism: 4,
          password: utf8.encode('password'),
          salt: utf8.encode('somesalt'),
          hashLen: 24,
          encoded: encodedPtr,
          encodedLen: encodedLen,
        ),
      );
      if (result == 0) {
        final encodedStr = encodedPtr.cast<Utf8>().toDartString();
        return encodedStr;
      } else {
        throw Exception(
          'Argon2i hash encoding failed with error code: $result',
        );
      }
    } finally {
      malloc.free(encodedPtr);
    }
  }

  @override
  void initState() {
    super.initState();
    sumResult = nativeArgon2.sum(1, 2);
    sumAsyncResult = nativeArgon2.sumAsync(3, 4);
    argon2iAsyncResult = _argon2i();
  }

  @override
  Widget build(BuildContext context) {
    const textStyle = TextStyle(fontSize: 12);
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
                  """
Expected result: 
https://github.com/P-H-C/phc-winner-argon2/tree/master

\$ echo -n "password" | ./argon2 somesalt -t 2 -m 16 -p 4 -l 24
Type:           Argon2i
Iterations:     2
Memory:         65536 KiB
Parallelism:    4
Hash:           45d7ac72e76f242b20b77b9bf9bf9d5915894e669a24e6c6
Encoded:        \$argon2i\$v=19\$m=65536,t=2,p=4\$c29tZXNhbHQ\$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
0.188 seconds
Verification ok""",
                  style: textStyle,
                  textAlign: TextAlign.left,
                ),

                spacerSmall,
                FutureBuilder<String>(
                  future: argon2iAsyncResult,
                  builder: (BuildContext context, AsyncSnapshot<String> value) {
                    final displayValue = (value.hasData)
                        ? value.data
                        : 'loading';
                    return Text(
                      'Actual result = $displayValue',
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
