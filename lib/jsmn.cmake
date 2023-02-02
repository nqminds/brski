if(NOT BUILD_ONLY_DOCS)
  FetchContent_Declare(
    jsmnlib
    GIT_REPOSITORY https://github.com/zserge/jsmn.git
    GIT_TAG 25647e692c7906b96ffd2b05ca54c097948e879c
    DOWNLOAD_DIR "${EP_DOWNLOAD_DIR}" # if empty string, uses default download dir
  )
  FetchContent_MakeAvailable(jsmnlib)

  add_library(jsmn::jsmn INTERFACE IMPORTED)
  target_include_directories(jsmn::jsmn INTERFACE "${jsmnlib_SOURCE_DIR}")
endif ()