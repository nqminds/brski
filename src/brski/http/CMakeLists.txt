set(CMAKE_C_EXTENSIONS ON) # needed to compile cpr
set(BRSKI_BUILD_TESTING "${BUILD_TESTING}")

FetchContent_GetProperties(cpr)
if(NOT cpr_POPULATED)
  FetchContent_Populate(cpr)
  # zlib-ng causes issues with `make install`, at least until v2.1.2
  add_subdirectory(${cpr_SOURCE_DIR} ${cpr_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()
# cpr overwrites the BUILD_TESTING var, so we need to reset it
set(BUILD_TESTING "${BRSKI_BUILD_TESTING}" CACHE BOOL "Build the testing tree." FORCE)

add_library(https_server https_server.cpp)
add_library(https_client https_client.cpp)
target_link_libraries(https_client PRIVATE os log cpr::cpr)

if (USE_CPPHTTPLIB_LIB)
  add_library(httplib_wrapper httplib_wrapper.cpp)
  target_link_libraries(httplib_wrapper PRIVATE os log httplib::httplib OpenSSL3::Crypto)

  target_compile_definitions(https_server PUBLIC WITH_CPPHTTPLIB_LIB)
  target_link_libraries(https_server PRIVATE os log httplib_wrapper)
endif()
