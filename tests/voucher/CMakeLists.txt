include_directories (
  "${PROJECT_SOURCE_DIR}/src"
)

add_cmocka_test(test_serialize
  SOURCES test_serialize.c
  LINK_LIBRARIES serialize log cmocka::cmocka
)

add_cmocka_test(test_voucher
  SOURCES test_voucher.c
  LINK_LIBRARIES voucher log cmocka::cmocka
)
