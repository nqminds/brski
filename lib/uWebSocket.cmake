
if(BUILD_uwebsocket AND NOT BUILD_ONLY_DOCS)
  FetchContent_Declare(
    uSockets_src
    URL https://github.com/uNetworking/uSockets/archive/refs/tags/v0.8.6.tar.gz
    URL_HASH SHA3_256=7ff33e17c2e49b253f27d70e3d24530c6016c88ae6771607ef96273915585757
    DOWNLOAD_DIR "${EP_DOWNLOAD_DIR}" # if empty string, uses default download dir
    DOWNLOAD_NAME uSockets-v0.8.6.tar.gz
  )

  FetchContent_Populate(uSockets_src)

  file(GLOB uSockets_SOURCE_FILES
    "${usockets_src_SOURCE_DIR}/src/*.c"
    "${usockets_src_SOURCE_DIR}/src/eventing/*.c"
    "${usockets_src_SOURCE_DIR}/src/crypto/*.c"
    "${usockets_src_SOURCE_DIR}/src/io_uring/*.c"
  )

  add_library(
    uSockets STATIC ${uSockets_SOURCE_FILES}
  )
  target_include_directories(uSockets PRIVATE "${usockets_src_SOURCE_DIR}/src")

  if (USE_VOUCHER_OPENSSL)
    add_compile_definitions(uSockets LIBUS_USE_OPENSSL)
    target_link_libraries(uSockets PUBLIC OpenSSL3::Crypto OpenSSL3::SSL)
  endif()

  ExternalProject_Add(uWebSockets-src
    URL https://github.com/uNetworking/uWebSockets/archive/refs/tags/v20.44.0.tar.gz
    URL_HASH SHA3_256=8dde1b906a49ec035f4156f0489b4c2bb02128e2a6de912820efb1f62857af44
    DOWNLOAD_DIR "${EP_DOWNLOAD_DIR}" # if empty string, uses default download dir
    DOWNLOAD_NAME uWebSockets-v20.44.0.tar.gz
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
    TEST_COMMAND ""
  )
  ExternalProject_Get_property(uWebSockets-src SOURCE_DIR)
  set(uWebSockets-SOURCE_DIR "${SOURCE_DIR}")

  add_library(uWebSockets INTERFACE)
  add_dependencies(uWebSockets uWebSockets-src)
  target_link_libraries(uWebSockets INTERFACE uSockets)
  target_include_directories(uWebSockets INTERFACE "${uWebSockets-SOURCE_DIR}/src")

endif()
