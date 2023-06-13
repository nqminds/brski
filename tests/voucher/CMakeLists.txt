add_executable(generate_test_certs generate_test_certs.c)
target_link_libraries(generate_test_certs PRIVATE voucher cmocka::cmocka)
add_test(NAME generate_test_certs
  COMMAND generate_test_certs "/tmp"
)

add_cmocka_test(test_array
  SOURCES test_array.c
  LINK_LIBRARIES array os log cmocka::cmocka
)

add_cmocka_test(test_keyvalue
  SOURCES test_keyvalue.c
  LINK_LIBRARIES keyvalue os log cmocka::cmocka
)

add_cmocka_test(test_crypto
  SOURCES test_crypto.c
  LINK_LIBRARIES crypto keyvalue array os log cmocka::cmocka
)

add_cmocka_test(test_serialize
  SOURCES test_serialize.c
  LINK_LIBRARIES serialize keyvalue os log cmocka::cmocka
)

add_cmocka_test(test_request
  SOURCES test_request.c
  LINK_LIBRARIES request voucher log cmocka::cmocka
)

add_cmocka_test(test_voucher
  SOURCES test_voucher.c
  LINK_LIBRARIES voucher log cmocka::cmocka
)
