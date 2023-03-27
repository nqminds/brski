include(GNUInstallDirs) # automagically setup install dir locations

#install(
#  TARGETS brski
#  RUNTIME
#)

install(
  TARGETS voucher
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/voucher
)

# usually /usr/local/lib/brksi
# BRSKI_private_lib_dir is set in main CMakeLists.txt, as we need it to set RPATH before targets

#configure_file(
#  "config.ini.in"
#  "config.ini"
#  ESCAPE_QUOTES # values are quoted, so we need to escape quotes
#  @ONLY # we only use @VAR_NAME@ syntax
#)
#configure_file(config.ini.in config.ini.in COPYONLY)

# /etc/brski/config.ini folder
# runs configure_file again and install config.ini.in
# install(SCRIPT "./CMakeModules/InstallConfigFile.cmake")

#install(CODE
#  "execute_process(
#    COMMAND ${CMAKE_COMMAND}
#      -D_project_lower=${_project_lower}
#      -DCMAKE_INSTALL_LIBDIR=${CMAKE_INSTALL_LIBDIR}
#      -Dbuild_dir=${CMAKE_BINARY_DIR}
#      -DCMAKE_INSTALL_PREFIX=\${CMAKE_INSTALL_PREFIX} # escape PREFIX so cmake --install --prefix works
#      -P ${CMAKE_SOURCE_DIR}/CMakeModules/InstallConfigFile.cmake
#  )"
#)
