cmake_minimum_required(VERSION 3.14.0) # required for FindSQLite3
cmake_policy(VERSION 3.14.0...3.24.0)

project(BRSKI
  VERSION 0.2.0
  HOMEPAGE_URL "https://github.com/nqminds/brski"
  DESCRIPTION "Bootstrapping Remote Secure Key Infrastructure (BRSKI)"
  LANGUAGES C CXX
)
# CMake proposal for semver https://gitlab.kitware.com/cmake/cmake/-/issues/23649
set(PROJECT_VERSION_PRERELEASE alpha.0)

set(
  PROJECT_VERSION
  "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}"
)
if (NOT "${PROJECT_VERSION_PRERELEASE}" STREQUAL "")
  string(APPEND PROJECT_VERSION "-${PROJECT_VERSION_PRERELEASE}")
endif()

if ("${PROJECT_VERSION_BUILD_IDENTIFIER}" STREQUAL "")
  # try to load build ID from environment variables only if on a git branch
  # (we assume git tags are static and therefore build ids are not needed)
  if (NOT "$ENV{GITHUB_SHA}" STREQUAL "" AND "$ENV{GITHUB_REF_TYPE}" STREQUAL "branch")
    set(PROJECT_VERSION_BUILD_IDENTIFIER "sha.$ENV{GITHUB_SHA}")
  endif()
endif()

if (NOT "${PROJECT_VERSION_BUILD_IDENTIFIER}" STREQUAL "")
  string(APPEND PROJECT_VERSION "+${PROJECT_VERSION_BUILD_IDENTIFIER}")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMakeModules")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/lib")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/docs")

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
  include(AddCMockaTest)
endif()

include(FetchContent)
include(ExternalProject)
include(CMakeDependentOption)
include(GenerateExportHeader)

string(TOLOWER ${CMAKE_HOST_SYSTEM_PROCESSOR} _sys)
string(TOLOWER ${PROJECT_NAME} _project_lower)

include(BrskiInstallLocations)

# Installation options
# RPATH must be set before defining targets
# $ORIGIN is so that shared libs can view other shared libs (e.g. libgrpc++ can see libxxx)
# $ORIGIN/lib is to support where we used to store shared libs
# ${BRSKI_full_private_lib_dir} is where private shared libs will be stored after `make install`
file(
  RELATIVE_PATH
  "BRSKI_relative_private_lib_dir"
  ${CMAKE_INSTALL_FULL_BINDIR} ${BRSKI_full_private_lib_dir}
)
message("Adding RPATH $ORIGIN relative path to: ${BRSKI_relative_private_lib_dir}")
set(
  CMAKE_INSTALL_RPATH
  "$ORIGIN" "$ORIGIN/lib" "${BRSKI_full_private_lib_dir}"
  "$ORIGIN/${BRSKI_relative_private_lib_dir}"
)

# currenty doesn't work if on, due to cyclical dependencies
set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "Build shared libraries")

option(BUILD_ONLY_DOCS "Build only docs" OFF)
option(BUILD_OPENSSL3_LIB "Build OpenSSL 3" OFF)
option(BUILD_WOLFSSL_LIB "Build WolfSSL" OFF)
option(BUILD_LIB_MININI "Builds minIni library" ON)
option(USE_CPPHTTPLIB_LIB "Build and use the cpp-httplib" OFF)

option(USE_VOUCHER_OPENSSL "Build voucher library with openssl support" OFF)
option(USE_VOUCHER_WOLFSSL "Build voucher library with wolfssl support" OFF)

option(SANITIZE_ADDRESS "Enable AddressSanitizer for debug builds." OFF)

cmake_dependent_option(CONFIGURE_COVERAGE "Configure for code coverage (requires lcov)" OFF BUILD_TESTING OFF)

# Default ExternalProject download directory.
# Useful for two reasons:
#   - A single download directory can be shared for all build presets
#   - Allows building/configuring when there is no internet connection
#     (e.g. OpenWRT SDK or default `pdebuild` environment)
set(EP_DOWNLOAD_DIR "" CACHE PATH "ExternalProject default DOWNLOAD_DIR")

# Set a default build type if none was specified
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to 'Debug' as none was specified.")
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build." FORCE)
  # Set the possible values of build type for cmake-gui
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release"
    "MinSizeRel" "RelWithDebInfo")
endif()

# Convert CMAKE_SYSTEM_NAME to os specifier that autoconf understands
function(get_autoconf_os system_name output_var)
  if (system_name STREQUAL "Linux")
    set(${output_var} "linux-gnu" PARENT_SCOPE)
  elseif (system_name STREQUAL "FreeBSD")
    set(${output_var} "freebsd" PARENT_SCOPE)
  else (system_name STREQUAL "Linux")
    message(FATAL_ERROR "'${system_name}' could not be converted to an autoconf os specifier")
  endif(system_name STREQUAL "Linux")
endfunction(get_autoconf_os)

get_autoconf_os(${CMAKE_HOST_SYSTEM_NAME} build_autoconf_os)
string(TOLOWER "${CMAKE_HOST_SYSTEM_PROCESSOR}-${build_autoconf_os}" build_autoconf_triple)
set(target_autoconf_triple "${CMAKE_C_COMPILER_TARGET}")
if (target_autoconf_triple STREQUAL "")
  # When cross-compiling debians use debuild, CMAKE_C_COMPILER_TARGET isn't set,
  # however, we can load the triple from CMAKE_LIBRARY_ARCHITECTURE instead
  set(target_autoconf_triple "${CMAKE_LIBRARY_ARCHITECTURE}")
endif()

if (CMAKE_CROSSCOMPILING)
  message("Cross-compiling, setting cross-compiling autoconf/pkg-config vars")
  message("Build (autoconf --build) autoconf triple is ${build_autoconf_triple}")
  message("Target (autoconf --host) autoconf triple is ${target_autoconf_triple}")
  if (target_autoconf_triple STREQUAL "")
    message(WARNING
      "BRSKI is configured for cross-compiling, but could not detect a valid target_autoconf_triple value."
      " This is normally loaded from CMAKE_C_COMPILER_TARGET or CMAKE_LIBRARY_ARCHITECTURE."
      " This may cause issues when cross-compiling sqlite/other libs.")
  endif()

  # tell PKG_CONFIG (required by hostap) to search correct folders when cross-compiling
  set(ENV{PKG_CONFIG_LIBDIR} "/usr/lib/${CMAKE_LIBRARY_ARCHITECTURE}/pkgconfig:/usr/share/pkgconfig")
  message("Setting cross-compiling PKG_CONFIG_LIBDIR to $ENV{PKG_CONFIG_LIBDIR}")
else(CMAKE_CROSSCOMPILING)
  # unset so that sqlite.cmake and etc. do not activate this
  unset(target_autoconf_triple)
endif(CMAKE_CROSSCOMPILING)

# C compiler options
set(CMAKE_C_STANDARD 11) # we use C11 raw-strings
set(CMAKE_C_STANDARD_REQUIRED TRUE)
if("${CMAKE_SYSTEM_NAME}" STREQUAL "FreeBSD")
  # we use some BSD exclusive functions, and there is no easy way to opt-in
  # to this on FreeBSD
  # __BSD_VISIBLE might work, but is non-official
  set(CMAKE_C_EXTENSIONS ON)
else()
  # only use standard C and opt-in to non-standard includes
  set(CMAKE_C_EXTENSIONS OFF)
endif()
add_compile_options(
  $<$<COMPILE_LANGUAGE:C>:-Wunused-variable>
  $<$<COMPILE_LANGUAGE:C>:-Wall>
  $<$<COMPILE_LANGUAGE:C>:-Wextra>
)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# use -std=c++11 rather than -std=gnu++11
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_LIBRARY_PATH "${CMAKE_LIBRARY_PATH};${CMAKE_CURRENT_BINARY_DIR}/lib")

# Include the libraries
include(cmocka)
include(openssl3)
include(httplib)
include(minIni)
include(jsmn)

# On Linux, creates a Threads::Threads target that points to pthread
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

# Most C11 implementation support threads.h, but it's technically optional and not yet supported on MSVC
include(CheckIncludeFile)
check_include_file(threads.h C11_STD_THREADS)
if (NOT C11_STD_THREADS)
  message(FATAL_ERROR "Your C11 stdlib does not support #include <threads.h>, see https://en.cppreference.com/w/c/thread")
endif()

add_library(Threads::C11Threads INTERFACE IMPORTED)
if("${CMAKE_SYSTEM_NAME}" STREQUAL "FreeBSD")
  # FreeBSD has a seperate C11 threads library we need to link to
  set_target_properties(Threads::C11Threads PROPERTIES INTERFACE_LINK_LIBRARIES "stdthreads")
else()
  set_target_properties(Threads::C11Threads PROPERTIES INTERFACE_LINK_LIBRARIES Threads::Threads)
endif()

# configure a header file to pass some of the CMake settings
# to the source code
configure_file(
  "version.h.in"
  "${PROJECT_BINARY_DIR}/version.h"
)

# Copy the default configuration file to the build folder
# This config file is for development, not for `make install` use
configure_file(
  "dev-config.ini.in"
  "${PROJECT_BINARY_DIR}/dev-config.ini"
  @ONLY
)

if (NOT BUILD_ONLY_DOCS)
  if (CONFIGURE_COVERAGE)
    include(CodeCoverage)
    # enable before the src() flag to enable code coverage
    append_coverage_compiler_flags()

    include(ProcessorCount)
    ProcessorCount(PROCESSOR_COUNT)

    setup_target_for_coverage_lcov(
      NAME coverage
      EXECUTABLE ctest
      EXECUTABLE_ARGS --output-on-failure -j "${PROCESSOR_COUNT}"
      EXCLUDE
        "${PROJECT_SOURCE_DIR}/lib/*"
        # These files are only in the build/ directory, but
        # llvm-cov gcov doesn't seem to like it
        "${PROJECT_SOURCE_DIR}/middlewares_list.c"
        # The _deps/ folder is created by CMake's FetchContent
        "${PROJECT_SOURCE_DIR}/_deps/*"
    )
  endif()

  if (SANITIZE_ADDRESS)
    include(CheckCCompilerFlag)

    set(CMAKE_REQUIRED_LINK_OPTIONS "-fsanitize=address")
    check_c_compiler_flag("-fsanitize=address" C_COMPILER_SUPPORTS_ASAN)
    set(CMAKE_REQUIRED_LINK_OPTIONS "")

    if (NOT C_COMPILER_SUPPORTS_ASAN)
      message(
        FATAL_ERROR
        "${CMAKE_C_COMPILER} version ${CMAKE_C_COMPILER_VERSION} does not "
        "support -fsanitize=address for target "
        "${CMAKE_SYSTEM_PROCESSOR}-${CMAKE_SYSTEM_NAME}"
      )
    endif()
    add_compile_options(
      $<$<CONFIG:Debug>:$<$<COMPILE_LANGUAGE:C>:-fsanitize=address>> # use AddressSanitizer to check addresses
      $<$<CONFIG:Debug>:$<$<COMPILE_LANGUAGE:CXX>:-fsanitize=address>> # use AddressSanitizer to check addresses
    )

    add_link_options(
      $<$<CONFIG:Debug>:$<$<LINK_LANGUAGE:C>:-fsanitize=address>> # need to link AddressSantizer lib
      $<$<CONFIG:Debug>:$<$<LINK_LANGUAGE:CXX>:-fsanitize=address>> # todo, maybe combine with the above line
    )
  endif()

  # src must be after codecoverage but before tests
  add_subdirectory(src)

  if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
    add_subdirectory(tests)
  endif()

  include(install)
endif ()

add_custom_target(archive COMMAND
    ${CMAKE_COMMAND} -E tar "cvz" "${_project_lower}-${_sys}-${PROJECT_VERSION}.tar.gz" --format=gnutar "${CMAKE_INSTALL_PREFIX}")
