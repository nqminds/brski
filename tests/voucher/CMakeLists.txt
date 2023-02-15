include_directories (
  "${PROJECT_SOURCE_DIR}/src"
)


if (USE_VOUCHER_WITH_OPENSSL OR USE_VOUCHER_WITH_WOLFSSL)
  add_cmocka_test(test_crypto
    SOURCES test_crypto.c
    LINK_LIBRARIES log cmocka::cmocka
  )
endif ()

if (USE_VOUCHER_WITH_OPENSSL AND (NOT USE_VOUCHER_WITH_WOLFSSL))
  target_link_libraries(test_crypto PRIVATE crypto_openssl)
elseif (USE_VOUCHER_WITH_WOLFSSL)
  target_link_libraries(test_crypto PRIVATE crypto_wolfssl)
endif()

add_cmocka_test(test_serialize
  SOURCES test_serialize.c
  LINK_LIBRARIES serialize log cmocka::cmocka
)

add_cmocka_test(test_voucher
  SOURCES test_voucher.c
  LINK_LIBRARIES voucher log cmocka::cmocka
)
