# Error on all C/C++ warnings in the tests/ directory if making a Debug build
add_compile_options($<$<CONFIG:Debug>:-Werror>)

# Link time optimization has some issues with linker `--wrap` (mocking) arg
# See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=88643 and
# https://sourceware.org/bugzilla/show_bug.cgi?id=24415
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION OFF)
string(REPLACE "-flto=auto" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}") # might be set by debian build

include_directories (
  "${PROJECT_SOURCE_DIR}/src"
)

# Folder to store certificates for tests
set(BRSKI_TEST_CERTS_DIR "${CMAKE_BINARY_DIR}/tests/brski-test-certs")
file(MAKE_DIRECTORY "${BRSKI_TEST_CERTS_DIR}")

add_subdirectory(brski)
add_subdirectory(voucher)
