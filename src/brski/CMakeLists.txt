add_subdirectory(http)
add_subdirectory(pledge)
add_subdirectory(registrar)
add_subdirectory(masa)

add_library(config OBJECT config.c)
target_link_libraries(config PRIVATE MinIni::minIni os log array crypto)

add_executable(brski brski.cpp)
target_link_libraries(brski PRIVATE pledge_request pledge_utils registrar_server masa_server config log)
target_include_directories(brski PRIVATE ${PROJECT_BINARY_DIR})

# Copy the default configuration file to the build folder
# This config file is for development, not for `make install` use
configure_file(
  "${PROJECT_SOURCE_DIR}/src/brski/dev-config.ini.in"
  "${PROJECT_BINARY_DIR}/src/brski/dev-config.ini"
  @ONLY
)
