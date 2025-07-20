import 'dart:async';
import 'dart:developer';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'native_argon2_bindings_generated.dart';

const String _libName = 'native_argon2';

class Argon2LibraryLoader {
  static Argon2LibraryLoader instance = Argon2LibraryLoader();

  String? _customLibraryPath;

  void configure({String? libraryPath}) {
    _customLibraryPath = libraryPath;
  }

  DynamicLibrary load() {
    if (_customLibraryPath != null) {
      log('Loading library from custom path: $_customLibraryPath');
      return DynamicLibrary.open(_customLibraryPath!);
    }

    if (Platform.isMacOS || Platform.isIOS) {
      return DynamicLibrary.open('$_libName.framework/$_libName');
    }
    if (Platform.isAndroid || Platform.isLinux) {
      return DynamicLibrary.open('lib$_libName.so');
    }
    if (Platform.isWindows) {
      return DynamicLibrary.open('$_libName.dll');
    }
    throw UnsupportedError('Unknown platform: ${Platform.operatingSystem}');
  }
}

class NativeArgon2 {
  final DynamicLibrary dylib;
  late final NativeArgon2Bindings bindings;

  int _nextRequestId = 0;
  final Map<int, Completer<dynamic>> _requests = {};

  SendPort? _helperIsolateSendPort;
  Completer<SendPort>? _isolateCompleter;

  NativeArgon2({DynamicLibrary? overrideDylib})
    : dylib = overrideDylib ?? Argon2LibraryLoader.instance.load() {
    bindings = NativeArgon2Bindings(dylib);
  }

  /// A very short-lived native function that can be called directly.
  int sum(int a, int b) => bindings.sum(a, b);

  /// A longer-lived native function that should be called in an isolate.
  Future<int> sumAsync(int a, int b) async {
    final sendPort = await _getHelperIsolateSendPort();

    final requestId = _nextRequestId++;
    final completer = Completer<int>();
    _requests[requestId] = completer;

    // Send request to isolate
    sendPort.send(_SumRequest(requestId, a, b));

    return completer.future;
  }

  /// Gets or initializes the helper isolate
  Future<SendPort> _getHelperIsolateSendPort() async {
    if (_helperIsolateSendPort != null) {
      return _helperIsolateSendPort!;
    }

    if (_isolateCompleter == null) {
      _isolateCompleter = Completer<SendPort>();
      _initializeHelperIsolate();
    }

    return _isolateCompleter!.future;
  }

  /// Initializes a helper isolate for running FFI code
  void _initializeHelperIsolate() {
    final receivePort = ReceivePort();
    receivePort.listen((dynamic data) {
      if (data is SendPort) {
        // Store the send port from the helper isolate
        _helperIsolateSendPort = data;
        _isolateCompleter!.complete(data);
        return;
      }

      if (data is _SumResponse) {
        // Process the response from the helper isolate
        final completer = _requests[data.id];
        if (completer != null) {
          _requests.remove(data.id);
          completer.complete(data.result);
        }
        return;
      } else if (data is _Argon2iHashResponse) {
        final completer = _requests[data.id];
        if (completer != null) {
          _requests.remove(data.id);
          completer.complete(data);
        }
        return;
      }

      throw UnsupportedError('Unsupported message: ${data.runtimeType}');
    });

    // Pass the current library configuration to the isolate
    final customLibPath = Argon2LibraryLoader.instance._customLibraryPath;

    // Start the helper isolate with configuration
    Isolate.spawn(
      _isolateMain,
      _IsolateSetup(receivePort.sendPort, customLibPath),
    );
  }

  static void _isolateMain(_IsolateSetup setup) {
    final receivePort = ReceivePort();
    if (setup.customLibraryPath != null) {
      Argon2LibraryLoader.instance.configure(
        libraryPath: setup.customLibraryPath,
      );
    }

    final dylib = Argon2LibraryLoader.instance.load();
    final bindings = NativeArgon2Bindings(dylib);

    receivePort.listen((dynamic data) {
      if (data is _SumRequest) {
        final result = bindings.sum_long_running(data.a, data.b);
        setup.sendPort.send(_SumResponse(data.id, result));
        return;
      } else if (data is _Argon2iHashRequest) {
        final params = data.params;
        final pwdPtr = calloc<Uint8>(params.password.length);
        final saltPtr = calloc<Uint8>(params.salt.length);

        try {
          pwdPtr.asTypedList(params.password.length).setAll(0, params.password);
          saltPtr.asTypedList(params.salt.length).setAll(0, params.salt);

          final result = bindings.argon2i_hash_encoded(
            params.tCost,
            params.mCost,
            params.parallelism,
            pwdPtr.cast<Void>(),
            params.password.length,
            saltPtr.cast<Void>(),
            params.salt.length,
            params.hashLen,
            params.encoded,
            params.encodedLen,
          );

          setup.sendPort.send(_Argon2iHashResponse(data.id, result));
          return;
        } finally {
          calloc.free(pwdPtr);
          calloc.free(saltPtr);
        }
      }

      throw UnsupportedError('Unsupported message: ${data.runtimeType}');
    });

    setup.sendPort.send(receivePort.sendPort);
  }

  int argon2iHashEncoded(Argon2EncodedParams params) {
    final pwdPtr = calloc<Uint8>(params.password.length);
    final saltPtr = calloc<Uint8>(params.salt.length);

    try {
      pwdPtr.asTypedList(params.password.length).setAll(0, params.password);
      saltPtr.asTypedList(params.salt.length).setAll(0, params.salt);

      final result = bindings.argon2i_hash_encoded(
        params.tCost,
        params.mCost,
        params.parallelism,
        pwdPtr.cast<Void>(),
        params.password.length,
        saltPtr.cast<Void>(),
        params.salt.length,
        params.hashLen,
        params.encoded,
        params.encodedLen,
      );
      return result;
    } finally {
      calloc.free(pwdPtr);
      calloc.free(saltPtr);
    }
  }

  Future<int> argon2iHashEncodedAsync(Argon2EncodedParams params) async {
    final sendPort = await _getHelperIsolateSendPort();
    final requestId = _nextRequestId++;
    final completer = Completer<_Argon2iHashResponse>();
    _requests[requestId] = completer;

    sendPort.send(_Argon2iHashRequest(requestId, params));

    final result = await completer.future;
    return result.result;
  }
}

/// Configuration data for setting up the helper isolate
class _IsolateSetup {
  final SendPort sendPort;
  final String? customLibraryPath;

  const _IsolateSetup(this.sendPort, this.customLibraryPath);
}

/// A request to compute `sum_long_running`.
class _SumRequest {
  final int id;
  final int a;
  final int b;

  const _SumRequest(this.id, this.a, this.b);
}

/// A response with the result of `sum_long_running`.
class _SumResponse {
  final int id;
  final int result;

  const _SumResponse(this.id, this.result);
}

class _Argon2iHashRequest {
  final int id;
  final Argon2EncodedParams params;

  _Argon2iHashRequest(this.id, this.params);
}

class _Argon2iHashResponse {
  final int id;
  final int result;

  _Argon2iHashResponse(this.id, this.result);
}

class Argon2EncodedParams {
  final int tCost;
  final int mCost;
  final int parallelism;
  final Uint8List password;
  final Uint8List salt;
  final int hashLen;
  final Pointer<Char> encoded;
  final int encodedLen;

  Argon2EncodedParams({
    this.tCost = 3,
    this.mCost = 12,
    this.parallelism = 1,
    required this.password,
    required this.salt,
    this.hashLen = 32,
    required this.encoded,
    required this.encodedLen,
  });
}
