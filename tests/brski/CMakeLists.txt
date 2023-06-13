set(TEST_CONFIG_INI_PATH "${CMAKE_BINARY_DIR}/tests/brski/test-config.ini")
configure_file("${CMAKE_CURRENT_LIST_DIR}/test-config.ini.in" "${TEST_CONFIG_INI_PATH}" @ONLY)

set(TEST_CONFIG_ADD_INI_PATH "${CMAKE_BINARY_DIR}/tests/brski/test-config-add.ini")
configure_file("${CMAKE_CURRENT_LIST_DIR}/test-config-add.ini.in" "${TEST_CONFIG_ADD_INI_PATH}" @ONLY)

add_cmocka_test(test_pledge_utils
  SOURCES test_pledge_utils.c
  LINK_LIBRARIES config pledge_utils os log cmocka::cmocka
)
set_tests_properties(test_pledge_utils PROPERTIES FIXTURES_REQUIRED test_certs)
target_compile_definitions(test_pledge_utils PRIVATE TEST_CONFIG_INI_PATH="${TEST_CONFIG_INI_PATH}")
target_compile_definitions(test_pledge_utils PRIVATE TEST_CONFIG_ADD_INI_PATH="${TEST_CONFIG_ADD_INI_PATH}")

# Run BRSKI CLI tests
if (UNIX)
  include(AddCTestDaemon)

  add_ctest_daemon(
    NAME test_masa
    COMMAND "$<TARGET_FILE:brski>" -c "${TEST_CONFIG_INI_PATH}" -dd masa
    FIXTURES_REQUIRED test_certs
  )

  add_ctest_daemon(
    NAME test_registrar
    COMMAND "$<TARGET_FILE:brski>" -c "${TEST_CONFIG_INI_PATH}" -dd registrar
    FIXTURES_REQUIRED "test_masa;test_certs"
  )

  add_test(
    NAME test_pledge
    COMMAND brski -c "${TEST_CONFIG_INI_PATH}" -dd preq
  )
  set_tests_properties(test_pledge PROPERTIES FIXTURES_REQUIRED "test_registrar;test_certs")
endif(UNIX)

#openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
#  -keyout pledge-cms.key -out pledge-cms.crt -subj "/CN=pledge-cms.com" \
#  -addext "subjectAltName=DNS:pledge-cms.com,DNS:www.pledge-cms.net,IP:10.0.1.1"
