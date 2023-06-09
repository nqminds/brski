# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (c) 2023 nquiringminds <info@nquiringminds.com>
#
# Redistribution and use is allowed according to the terms of the MIT license.
# For details see the
# https://github.com/nqminds/brski/blob/82dd497a6db11946d31259fc0b4bf19dfd778d83/LICENSE
# file.

#.rst:
# CTestDaemon
# -------------
#
# This file provides some helper functions to make it easier to add ctest
# fixtures that start/stop a daemon, as explained in
# `CTest able to daemonize fixtures?`_
#
# .. _`CTest able to daemonize fixtures?`: https://discourse.cmake.org/t/ctest-able-to-daemonize-fixtures/1012
#
# Functions provided
# ------------------
#
# ::
#
#   add_ctest_daemon(NAME fixture_name
#                    COMMAND src1 src2 ... srcN
#                   )
#
# ``fixture_name``:
#   Required, the name of the CTest fixture to define. The tests will also be
#   named as:
#       - ``<fixture_name>_START`` - Starts the daemon.
#       - ``<fixture_name>_STOP`` - Stops the daemon (errors if daemon is already stopped)
#       - ``<fixture_name>_OUTPUT`` - Prints the stdout/stderr logs
#
# ``COMMAND``:
#   Required, the command to run.
#
# ``FIXTURES_REQUIRED``:
#   Optional, list of fixtures this fixture requires, if any.
#
# Example:
#
# .. code-block:: cmake
#
#   add_ctest_daemon(NAME my_server COMMAND sleep 5)
#   add_test(NAME requires_my_server COMMAND my-example-cmd)
#   set_tests_properties(requires_my_server PROPERTIES FIXTURES_REQUIRED my_server)
#
function(add_ctest_daemon)
  set(oneValueArgs NAME FIXTURES_REQUIRED)
  set(multiValueArgs COMMAND)
  cmake_parse_arguments(ADD_CTEST_DAEMON "${options}" "${oneValueArgs}"
                        "${multiValueArgs}" ${ARGN} )

  if (NOT DEFINED ADD_CTEST_DAEMON_NAME)
    message(FATAL_ERROR "You must provide a name")
  endif()

  if (NOT DEFINED ADD_CTEST_DAEMON_COMMAND)
    message(FATAL_ERROR "You must provide a command")
  endif()

  if (NOT UNIX)
    message(FATAL_ERROR "add_ctest_daemon() currently requires a POSIX shell")
  endif()

  # quote every arg with '' (and escape any existing ')
  list(TRANSFORM ADD_CTEST_DAEMON_COMMAND REPLACE "'" "'\"'\"'")
  list(TRANSFORM ADD_CTEST_DAEMON_COMMAND APPEND "'")
  list(TRANSFORM ADD_CTEST_DAEMON_COMMAND PREPEND "'")
  list(JOIN ADD_CTEST_DAEMON_COMMAND " " escaped_command)

  set(PID_FILE "${CMAKE_CURRENT_BINARY_DIR}/${ADD_CTEST_DAEMON_NAME}.pid")
  set(STDOUT_FILE "${CMAKE_CURRENT_BINARY_DIR}/${ADD_CTEST_DAEMON_NAME}.stdout.txt")
  set(STDERR_FILE "${CMAKE_CURRENT_BINARY_DIR}/${ADD_CTEST_DAEMON_NAME}.stderr.txt")

  add_test(
    NAME "${ADD_CTEST_DAEMON_NAME}_start"
    COMMAND sh -c "${escaped_command} 1> '${STDOUT_FILE}' 2> '${STDERR_FILE}' & echo \"$!\" > '${PID_FILE}';"
  )

  set(cleanup_command_and_list
    "echo \"Killing PID $PID\" >&2"
    "kill \"$PID\"" # soft kill
    "(sleep 1 && kill -9 \"$PID\" &) > /dev/null 2>/dev/null" # force kill after 1 second
    "tail --pid=\"$PID\" -f /dev/null" # wait for command to quit
    "rm '${PID_FILE}'"
  )
  list(JOIN cleanup_command_and_list " && " cleanup_command_and_list)

  add_test(
    NAME "${ADD_CTEST_DAEMON_NAME}_stop"
    COMMAND sh -c "PID=\"$(cat '${PID_FILE}')\"; ${cleanup_command_and_list}"
  )

  add_test(
    NAME "${ADD_CTEST_DAEMON_NAME}_output"
    COMMAND sh -c "cat '${STDOUT_FILE}' && cat '${STDERR_FILE}' >&2 && rm '${STDOUT_FILE}' '${STDERR_FILE}'"
  )

  set_tests_properties("${ADD_CTEST_DAEMON_NAME}_start" PROPERTIES FIXTURES_SETUP "${ADD_CTEST_DAEMON_NAME}")
  set_tests_properties("${ADD_CTEST_DAEMON_NAME}_stop" PROPERTIES FIXTURES_CLEANUP "${ADD_CTEST_DAEMON_NAME}")
  set_tests_properties("${ADD_CTEST_DAEMON_NAME}_output" PROPERTIES
    FIXTURES_CLEANUP "${ADD_CTEST_DAEMON_NAME}"
    DEPENDS "${ADD_CTEST_DAEMON_NAME}_stop"
  )

  if (ADD_CTEST_DAEMON_FIXTURES_REQUIRED)
    set_tests_properties("${ADD_CTEST_DAEMON_NAME}_start" PROPERTIES FIXTURES_REQUIRED "${ADD_CTEST_DAEMON_FIXTURES_REQUIRED}")
    set_tests_properties("${ADD_CTEST_DAEMON_NAME}_stop" PROPERTIES FIXTURES_REQUIRED "${ADD_CTEST_DAEMON_FIXTURES_REQUIRED}")
  endif()
endfunction(add_ctest_daemon)
