if (C_COMPILER_SUPPORTS_ANALYZER)
  add_compile_options(
    # Enable GCC static analysis if compiling in Debug mode
    # (warning, is very slow)
    $<$<AND:$<C_COMPILER_ID:GNU>,$<CONFIG:Debug>>:-fanalyzer>
  )
endif()

add_library(os OBJECT os.c)
set_target_properties(os PROPERTIES
  C_EXTENSIONS ON # requires BSD gettimeofday
  POSITION_INDEPENDENT_CODE ON
)

add_library(log OBJECT log.c)

# requires POSIX mode_t/umask functions, and BSD gettimeofday
set_target_properties(log PROPERTIES C_EXTENSIONS ON POSITION_INDEPENDENT_CODE ON)
