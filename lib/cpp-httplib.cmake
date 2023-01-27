if(BUILD_CPPHTTPLIB_LIB AND NOT BUILD_ONLY_DOCS)
  FetchContent_Declare(
    cpp-httplib
    URL https://github.com/yhirose/cpp-httplib/archive/refs/tags/v0.11.4.tar.gz
    URL_HASH SHA3_256=9aedcbec09b7b3b01c78cc80822c505846d73928a72ae96eb907b1f467eee649
    DOWNLOAD_DIR "${EP_DOWNLOAD_DIR}" # if empty string, uses default download dir
  )
  set(HTTPLIB_REQUIRE_OPENSSL ON CACHE BOOL "Enable OpenSSL for the library" FORCE)
endif ()