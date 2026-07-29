{
  "targets": [
    {
      "target_name": "trusted_clock_client",
      "sources": [
        "native/trusted_clock_client.cc",
        "native/trusted_clock_node.cc"
      ],
      "libraries": [
        "-lbsm",
        "-framework CoreFoundation",
        "-framework Security"
      ],
      "defines": [
        "NAPI_VERSION=9"
      ],
      "xcode_settings": {
        "CLANG_CXX_LANGUAGE_STANDARD": "c++17",
        "CLANG_CXX_LIBRARY": "libc++",
        "MACOSX_DEPLOYMENT_TARGET": "13.0",
        "GCC_ENABLE_CPP_EXCEPTIONS": "NO",
        "GCC_ENABLE_CPP_RTTI": "NO",
        "GCC_TREAT_WARNINGS_AS_ERRORS": "YES",
        "WARNING_CFLAGS": [
          "-Wall",
          "-Wextra",
          "-Wpedantic",
          "-Wshadow",
          "-Wconversion",
          "-Wsign-conversion"
        ]
      }
    },
    {
      "target_name": "trusted_clock_service",
      "type": "executable",
      "sources": [
        "native/trusted_clock_service.cc"
      ],
      "libraries": [
        "-lbsm",
        "-framework CoreFoundation",
        "-framework Security"
      ],
      "xcode_settings": {
        "CLANG_CXX_LANGUAGE_STANDARD": "c++17",
        "CLANG_CXX_LIBRARY": "libc++",
        "MACOSX_DEPLOYMENT_TARGET": "13.0",
        "GCC_ENABLE_CPP_EXCEPTIONS": "NO",
        "GCC_ENABLE_CPP_RTTI": "NO",
        "GCC_TREAT_WARNINGS_AS_ERRORS": "YES",
        "WARNING_CFLAGS": [
          "-Wall",
          "-Wextra",
          "-Wpedantic",
          "-Wshadow",
          "-Wconversion",
          "-Wsign-conversion"
        ]
      }
    }
  ]
}

