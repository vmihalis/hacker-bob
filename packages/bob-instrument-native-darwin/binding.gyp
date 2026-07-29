{
  "targets": [
    {
      "target_name": "peer_credentials",
      "sources": [
        "native/peer_credentials.cc"
      ],
      "libraries": [
        "-lbsm",
        "-lproc",
        "-framework CoreFoundation",
        "-framework Security"
      ],
      "defines": [
        "NAPI_VERSION=9"
      ],
      "xcode_settings": {
        "CLANG_CXX_LANGUAGE_STANDARD": "c++17",
        "CLANG_CXX_LIBRARY": "libc++",
        "MACOSX_DEPLOYMENT_TARGET": "11.0",
        "GCC_ENABLE_CPP_EXCEPTIONS": "YES"
      }
    }
  ]
}
