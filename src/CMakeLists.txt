add_compile_options(
  # Error on all C/C++ warnings in the src/ directory if making a Debug build
  $<$<CONFIG:Debug>:-Werror>
  # Warn/error if using a non-const pointer to a string literal
  $<$<COMPILE_LANGUAGE:C>:-Wwrite-strings>
  $<$<COMPILE_LANGUAGE:C>:-Wpedantic>
  $<$<COMPILE_LANGUAGE:C>:-Wformat-security> # required by debian builds
  $<$<COMPILE_LANGUAGE:C>:-Wfloat-equal> # warn/error if checking for equality between floats
  $<$<COMPILE_LANGUAGE:C>:-Wnull-dereference> # warn if dereferencing NULL
  $<$<COMPILE_LANGUAGE:C>:-Wstrict-prototypes> # warn if creating a function without specifiying args
)

add_executable(brski-server brski-server.cpp)
target_link_libraries(brski-server PRIVATE OpenSSL3::Crypto httplib::httplib)
target_include_directories(brski-server PRIVATE ${PROJECT_BINARY_DIR})