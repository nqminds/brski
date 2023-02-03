add_library(serialize serialize.c)
target_link_libraries(serialize PRIVATE os)

add_library(voucher voucher.c)
target_link_libraries(voucher PUBLIC jsmn::jsmn PRIVATE serialize os)
