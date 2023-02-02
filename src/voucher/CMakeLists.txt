add_library(voucher voucher.c)
target_link_libraries(voucher PUBLIC jsmn::jsmn)