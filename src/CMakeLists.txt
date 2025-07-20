# The Flutter tooling requires that developers have CMake 3.10 or later
# installed. You should not increase this version, as doing so will cause
# the plugin to fail to compile for some customers of the plugin.
cmake_minimum_required(VERSION 3.10)

project(native_argon2_library VERSION 0.0.1 LANGUAGES C)

add_library(native_argon2 SHARED
  "argon2.c"
  "core.c"
  "blake2/blake2b.c"
  "encoding.c"
  "ref.c"
  "thread.c"
)

target_include_directories(native_argon2 PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
)

set_target_properties(native_argon2 PROPERTIES
  PUBLIC_HEADER argon2.h
  OUTPUT_NAME "native_argon2"
)

target_compile_definitions(native_argon2 PUBLIC DART_SHARED_LIB)

if (ANDROID)
  # Support Android 15 16k page size
  target_link_options(native_argon2 PRIVATE "-Wl,-z,max-page-size=16384")
endif()
