# Voucher Library Usage

## Example CMakeLists.txt file
Below is an example `cmake` config file to import the voucher library into a `cmake` project and use it with OpenSSL. The path for the static voucher library file `libvoucher.a` is set by the 
`LIBVOUCHER_LIBRARY` variable and the voucher library include path is set by `LIBVOUCHER_INCLUDE_PATH` variable.

```cmake
cmake_minimum_required(VERSION 3.1...3.26)

project(
  LibTest
  VERSION 1.0
  LANGUAGES C)

find_package(OpenSSL 3 MODULE REQUIRED COMPONENTS Crypto SSL)
message("Found OpenSSL ${OPENSSL_VERSION} crypto library")
add_library(OpenSSL3::Crypto ALIAS OpenSSL::Crypto)
add_library(OpenSSL3::SSL ALIAS OpenSSL::SSL)
set(LIBOPENSSL3_INCLUDE_PATH "${OPENSSL_INCLUDE_DIR}")

set(LIBVOUCHER_INCLUDE_PATH "${CMAKE_SOURCE_DIR}/include/voucher")
set(LIBVOUCHER_LIB_PATH "${CMAKE_SOURCE_DIR}/lib")
set(LIBVOUCHER_LIBRARY "${LIBVOUCHER_LIB_PATH}/libvoucher.a")

add_library(Voucher::Voucher STATIC IMPORTED)
set_target_properties(Voucher::Voucher PROPERTIES
  IMPORTED_LOCATION "${LIBVOUCHER_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${LIBVOUCHER_INCLUDE_PATH}"
)

add_executable(libtest libtest.c)
target_link_libraries(libtest PRIVATE Voucher::Voucher OpenSSL::Crypto)
```