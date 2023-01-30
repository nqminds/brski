add_library(log log.c)

# requires POSIX mode_t/umask functions, and BSD gettimeofday
set_target_properties(log PROPERTIES C_EXTENSIONS ON POSITION_INDEPENDENT_CODE ON)

add_library(allocs allocs.c)
