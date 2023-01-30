add_library(log log.c)

# requires POSIX mode_t/umask functions, and BSD gettimeofday
set_target_properties(log PROPERTIES C_EXTENSIONS ON POSITION_INDEPENDENT_CODE ON)

add_library(os os.c)
set_target_properties(os PROPERTIES
  C_EXTENSIONS ON # requires BSD gettimeofday
  POSITION_INDEPENDENT_CODE ON
)
