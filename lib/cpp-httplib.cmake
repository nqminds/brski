if(BUILD_CPPHTTPLIB_LIB AND NOT BUILD_ONLY_DOCS)
  FetchContent_Declare(
    cpp-httplib
    URL https://github.com/yhirose/cpp-httplib/archive/refs/tags/v0.11.4.tar.gz
    URL_HASH SHA3_256=b19ecc19dc73c239f5bf4ab4816cf630390533590745c552204f5d78e6a502bc
    DOWNLOAD_DIR "${EP_DOWNLOAD_DIR}" # if empty string, uses default download dir
  )
  set(HTTPLIB_REQUIRE_OPENSSL ON CACHE BOOL "Enable OpenSSL for the library" FORCE)

  # create static lib using -fPIC, so we can make it into a sharedobject later
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
  FetchContent_MakeAvailable(cpp-httplib)
endif ()