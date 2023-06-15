if(BUILD_ONLY_DOCS)
elseif(BUILD_JSMN)
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
else()
  find_path(jsmn_INCLUDE_DIR
    NAMES jsmn.h
    DOC "Folder that contains the jsmn.h header"
  )
  if (jsmn_INCLUDE_DIR STREQUAL "jsmn_INCLUDE_DIR-NOTFOUND")
    message(FATAL_ERROR
      "Could not find jsmn_INCLUDE_DIR using the following files: jsmn.h "
      "You can set -DBUILD_JSMN=ON to automatically download it.")
  endif()
  mark_as_advanced(jsmn_INCLUDE_DIR)
  add_library(jsmn::jsmn INTERFACE IMPORTED)
  target_include_directories(jsmn::jsmn INTERFACE "${jsmn_INCLUDE_DIR}")
endif ()
