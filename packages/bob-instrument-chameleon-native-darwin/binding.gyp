{
  "targets": [
    {
      "target_name": "serial_custody",
      "sources": [
        "native/serial_custody.cc"
      ],
      "defines": [
        "NAPI_VERSION=9"
      ],
      "xcode_settings": {
        "CLANG_CXX_LANGUAGE_STANDARD": "c++17",
        "CLANG_CXX_LIBRARY": "libc++",
        "MACOSX_DEPLOYMENT_TARGET": "11.0",
        "GCC_ENABLE_CPP_EXCEPTIONS": "NO"
      }
    },
    {
      "target_name": "direct_cdc_custody",
      "sources": [
        "native/direct_cdc_custody.mm"
      ],
      "libraries": [
        "-framework Foundation",
        "-framework IOKit",
        "-framework IOUSBHost",
        "-framework Security"
      ],
      "defines": [
        "NAPI_VERSION=9"
      ],
      "xcode_settings": {
        "CLANG_CXX_LANGUAGE_STANDARD": "c++17",
        "CLANG_CXX_LIBRARY": "libc++",
        "CLANG_ENABLE_OBJC_ARC": "YES",
        "MACOSX_DEPLOYMENT_TARGET": "11.0",
        "GCC_ENABLE_CPP_EXCEPTIONS": "NO"
      }
    },
    {
      "target_name": "native_dispatch_custodian",
      "sources": [
        "native/native_dispatch_custodian.cc"
      ],
      "defines": [
        "NAPI_VERSION=9"
      ],
      "xcode_settings": {
        "CLANG_CXX_LANGUAGE_STANDARD": "c++17",
        "CLANG_CXX_LIBRARY": "libc++",
        "MACOSX_DEPLOYMENT_TARGET": "11.0",
        "GCC_ENABLE_CPP_EXCEPTIONS": "NO",
        "GCC_ENABLE_CPP_RTTI": "NO",
        "GCC_TREAT_WARNINGS_AS_ERRORS": "YES",
        "OTHER_CPLUSPLUSFLAGS": [
          "-Wall",
          "-Wextra",
          "-Wconversion",
          "-Wsign-conversion",
          "-Wshadow",
          "-Wpedantic",
          "-Wno-deprecated-declarations"
        ]
      }
    }
  ]
}
