{
  "targets": [
    {
      "target_name": "safety_watchdog_fixture",
      "type": "executable",
      "sources": [
        "native/safety_watchdog.cc"
      ],
      "xcode_settings": {
        "CLANG_CXX_LANGUAGE_STANDARD": "c++17",
        "CLANG_CXX_LIBRARY": "libc++",
        "MACOSX_DEPLOYMENT_TARGET": "11.0",
        "GCC_ENABLE_CPP_EXCEPTIONS": "NO"
      }
    }
  ]
}
