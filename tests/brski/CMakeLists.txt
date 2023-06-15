# copy files from brski-test-certs, adjusting the OpenSSL validity to current date
file(GLOB brskiTestCerts RELATIVE "${CMAKE_CURRENT_LIST_DIR}" "${CMAKE_CURRENT_LIST_DIR}/brski-test-certs/*.crt")
foreach(brskiTestCert ${brskiTestCerts})
  string(REGEX REPLACE "\.crt$" ".key" brskiTestCertKey "${brskiTestCert}")

  configure_file("${brskiTestCertKey}" "${brskiTestCertKey}" COPYONLY)

  if(brskiTestCert MATCHES "cms\.crt$")
    # TODO: figure out how to adjust the validity of these certificates
    # Currently, we can just copy them over, since even if they're invalid,
    # they still seem to work
    configure_file("${brskiTestCert}" "${brskiTestCert}" COPYONLY)
  elseif(brskiTestCert MATCHES "ca\.crt$")
    # recreate CA cert using old CA cert
    add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${brskiTestCert}"
      COMMAND openssl x509 -days 14
        -in "${CMAKE_CURRENT_LIST_DIR}/${brskiTestCert}"
        -signkey "${CMAKE_CURRENT_LIST_DIR}/${brskiTestCertKey}"
        -out "${CMAKE_CURRENT_BINARY_DIR}/${brskiTestCert}"
      DEPENDS
        "${CMAKE_CURRENT_LIST_DIR}/${brskiTestCert}"
        "${CMAKE_CURRENT_LIST_DIR}/${brskiTestCertKey}"
    )
  else()
    string(REGEX REPLACE "\.crt$" ".csr" brskiTestCertCsr "${brskiTestCert}")
    string(REGEX REPLACE "\.crt$" "-ca.crt" brskiTestCACert "${brskiTestCert}")
    string(REGEX REPLACE "\.crt$" "-ca.key" brskiTestCACertKey "${brskiTestCert}")

    add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${brskiTestCertCsr}"
      COMMAND openssl x509 -x509toreq
        -in "${CMAKE_CURRENT_LIST_DIR}/${brskiTestCert}"
        -signkey "${CMAKE_CURRENT_LIST_DIR}/${brskiTestCertKey}"
        -out "${CMAKE_CURRENT_BINARY_DIR}/${brskiTestCertCsr}"
      DEPENDS "${CMAKE_CURRENT_LIST_DIR}/${brskiTestCert}" "${CMAKE_CURRENT_LIST_DIR}/${brskiTestCertKey}"
    )

    add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${brskiTestCert}"
      COMMAND openssl x509 -req -days 14
        -in "${CMAKE_CURRENT_BINARY_DIR}/${brskiTestCertCsr}"
        -CA "${CMAKE_CURRENT_BINARY_DIR}/${brskiTestCACert}"
        -CAkey "${CMAKE_CURRENT_BINARY_DIR}/${brskiTestCACertKey}"
        -CAcreateserial
        -out "${CMAKE_CURRENT_BINARY_DIR}/${brskiTestCert}"
      DEPENDS
        "${CMAKE_CURRENT_BINARY_DIR}/${brskiTestCertCsr}"
        "${CMAKE_CURRENT_BINARY_DIR}/${brskiTestCACert}"
        "${CMAKE_CURRENT_BINARY_DIR}/${brskiTestCACertKey}"
        "${CMAKE_CURRENT_LIST_DIR}/${brskiTestCertKey}"
    )
  endif()
endforeach(brskiTestCert "${brskiTestCerts}")
list(TRANSFORM brskiTestCerts PREPEND "${CMAKE_CURRENT_BINARY_DIR}/" OUTPUT_VARIABLE outputBrskiTestCerts)
add_custom_target(brskiTestCerts ALL
  DEPENDS ${outputBrskiTestCerts}
)

set(TEST_CONFIG_INI_PATH "${CMAKE_BINARY_DIR}/tests/brski/test-config.ini")
configure_file("${CMAKE_CURRENT_LIST_DIR}/test-config.ini.in" "${TEST_CONFIG_INI_PATH}" @ONLY)

set(TEST_CONFIG_ADD_INI_PATH "${CMAKE_BINARY_DIR}/tests/brski/test-config-add.ini")
configure_file("${CMAKE_CURRENT_LIST_DIR}/test-config-add.ini.in" "${TEST_CONFIG_ADD_INI_PATH}" @ONLY)

add_cmocka_test(test_pledge_utils
  SOURCES test_pledge_utils.c
  LINK_LIBRARIES config pledge_utils os log cmocka::cmocka
)
target_compile_definitions(test_pledge_utils PRIVATE TEST_CONFIG_INI_PATH="${TEST_CONFIG_INI_PATH}")
target_compile_definitions(test_pledge_utils PRIVATE TEST_CONFIG_ADD_INI_PATH="${TEST_CONFIG_ADD_INI_PATH}")

# Run BRSKI CLI tests
if (UNIX)
  include(AddCTestDaemon)

  add_ctest_daemon(
    NAME test_masa
    COMMAND "$<TARGET_FILE:brski>" -c "${TEST_CONFIG_INI_PATH}" -dd masa
  )

  add_ctest_daemon(
    NAME test_registrar
    COMMAND "$<TARGET_FILE:brski>" -c "${TEST_CONFIG_INI_PATH}" -dd registrar
    FIXTURES_REQUIRED test_masa
  )

  # add a tiny delay, just for registrar to start listening on https
  add_test(NAME wait_for_registrar COMMAND sleep 0.1)
  set_tests_properties(wait_for_registrar PROPERTIES
    FIXTURES_SETUP test_registrar
    DEPENDS test_registrar_start
  )

  add_test(
    NAME test_pledge
    COMMAND brski -c "${TEST_CONFIG_INI_PATH}" -dd preq
  )
  set_tests_properties(test_pledge PROPERTIES FIXTURES_REQUIRED test_registrar)
endif(UNIX)

#openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
#  -keyout pledge-cms.key -out pledge-cms.crt -subj "/CN=pledge-cms.com" \
#  -addext "subjectAltName=DNS:pledge-cms.com,DNS:www.pledge-cms.net,IP:10.0.1.1"
