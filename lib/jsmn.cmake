if(NOT BUILD_ONLY_DOCS)
  FetchContent_Declare(
    jsmnlib
    URL https://github.com/zserge/jsmn/archive/refs/tags/v1.1.0.tar.gz
    URL_HASH SHA3_256=f976110eda97a712fa4c99d1f3b396987d0905b2c2f8c7ad32286c15a74368e9
    DOWNLOAD_DIR "${EP_DOWNLOAD_DIR}" # if empty string, uses default download dir
    DOWNLOAD_NAME jsmn-v1.1.0.tar.gz
  )
  FetchContent_MakeAvailable(jsmnlib)

  add_library(jsmn::jsmn INTERFACE IMPORTED)
  target_include_directories(jsmn::jsmn INTERFACE "${jsmnlib_SOURCE_DIR}")
endif ()
