include_directories (
  "${PROJECT_SOURCE_DIR}/src"
)

add_cmocka_test(test_vutils
  SOURCES test_vutils.c
  LINK_LIBRARIES vutils log cmocka::cmocka
)

add_cmocka_test(test_crypto
  SOURCES test_crypto.c
  LINK_LIBRARIES vutils log cmocka::cmocka
)

add_cmocka_test(test_serialize
  SOURCES test_serialize.c
  LINK_LIBRARIES serialize log cmocka::cmocka
)

add_cmocka_test(test_request
  SOURCES test_request.c
  LINK_LIBRARIES voucher serialize log cmocka::cmocka
)

add_cmocka_test(test_voucher
  SOURCES test_voucher.c
  LINK_LIBRARIES voucher log cmocka::cmocka
)

target_link_libraries(test_crypto PRIVATE voucher os)
target_link_libraries(test_voucher PRIVATE voucher os)
