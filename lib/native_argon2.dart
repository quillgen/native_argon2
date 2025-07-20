import 'dart:async';
import 'dart:developer';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';

import 'native_argon2_bindings_generated.dart';

const String _libName = 'native_argon2';

/// Library loader that can be configured for different environments
class Argon2LibraryLoader {
  // Static instance for global configuration
  static Argon2LibraryLoader instance = Argon2LibraryLoader();

  // Custom path that can be injected for testing
  String? _customLibraryPath;

  // Configure the loader with a custom path
  void configure({String? libraryPath}) {
    _customLibraryPath = libraryPath;
  }

  // Load the appropriate library based on configuration
  DynamicLibrary load() {
    // Use custom path if provided
    if (_customLibraryPath != null) {
      log('Loading library from custom path: $_customLibraryPath');
      return DynamicLibrary.open(_customLibraryPath!);
    }

    // Default platform-specific paths
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

  // For managing async requests
  int _nextRequestId = 0;
  final Map<int, Completer<int>> _requests = {};

  // Lazy-initialized helper isolate
  SendPort? _helperIsolateSendPort;
  Completer<SendPort>? _isolateCompleter;

  // Constructor with dependency injection
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

  /// Static method to run in the helper isolate
  static void _isolateMain(_IsolateSetup setup) {
    // Create a receive port for incoming messages
    final receivePort = ReceivePort();

    // Configure the library loader in this isolate with the same path
    if (setup.customLibraryPath != null) {
      Argon2LibraryLoader.instance.configure(
        libraryPath: setup.customLibraryPath,
      );
    }

    // Load the library using the configured loader
    final dylib = Argon2LibraryLoader.instance.load();
    final bindings = NativeArgon2Bindings(dylib);

    // Listen for requests
    receivePort.listen((dynamic data) {
      if (data is _SumRequest) {
        // Execute the long-running FFI function
        final result = bindings.sum_long_running(data.a, data.b);

        // Send the result back
        setup.sendPort.send(_SumResponse(data.id, result));
        return;
      }

      throw UnsupportedError('Unsupported message: ${data.runtimeType}');
    });

    // Send this isolate's send port to the main isolate
    setup.sendPort.send(receivePort.sendPort);
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
