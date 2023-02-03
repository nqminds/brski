add_library(serialize serialize.c)
target_link_libraries(serialize PRIVATE os)
target_compile_definitions(serialize PRIVATE _DEFAULT_SOURCE _BSD_SOURCE)

add_library(voucher voucher.c)
target_link_libraries(voucher PUBLIC jsmn::jsmn PRIVATE serialize os)
