include(GNUInstallDirs) # automagically setup install dir locations
install(
  TARGETS brski
  RUNTIME
)

# usually /usr/local/lib/brksi (or /usr/lib/brski for .deb)
# BRSKI_private_lib_dir is set in main CMakeLists.txt, as we need it to set RPATH before targets
# currently only hostapd, so it doesn't conflict with other hostapds
configure_file(
  "config.ini.in"
  "config.ini"
  ESCAPE_QUOTES # values are quoted, so we need to escape quotes
  @ONLY # we only use @VAR_NAME@ syntax
)
configure_file(config.ini.in config.ini.in COPYONLY)

# /etc/brski/config.ini folder
# runs configure_file again and install config.ini.in
# install(SCRIPT "./CMakeModules/InstallConfigFile.cmake")
install(CODE
  "execute_process(
    COMMAND ${CMAKE_COMMAND}
      -D_project_lower=${_project_lower}
      -DCMAKE_INSTALL_LIBDIR=${CMAKE_INSTALL_LIBDIR}
      -Dbuild_dir=${CMAKE_BINARY_DIR}
      -DCMAKE_INSTALL_PREFIX=\${CMAKE_INSTALL_PREFIX} # escape PREFIX so cmake --install --prefix works
      -P ${CMAKE_SOURCE_DIR}/CMakeModules/InstallConfigFile.cmake
  )"
)

if(BUILD_OPENSSL3_LIB AND LIBCRYPTO_LIB AND LIBOPENSSL3_LIB_PATH)
  install(DIRECTORY "${LIBOPENSSL3_LIB_PATH}/" DESTINATION ${BRSKI_private_lib_dir})
endif ()
