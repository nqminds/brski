add_library(log log.c)

# requires POSIX mode_t/umask functions, and BSD gettimeofday
set_target_properties(log PROPERTIES C_EXTENSIONS ON POSITION_INDEPENDENT_CODE ON)

add_library(allocs allocs.c)

add_library(https_server https_server.cpp)
if (USE_CPPHTTPLIB_LIB)
  target_compile_definitions(https_server PUBLIC WITH_CPPHTTPLIB_LIB)
  target_link_libraries(https_server PRIVATE allocs log httplib::httplib)
endif()