add_library(https_server https_server.cpp)
if (USE_CPPHTTPLIB_LIB)
  add_library(httplib_wrapper httplib_wrapper.cpp)
  target_link_libraries(httplib_wrapper PRIVATE os log httplib::httplib)

  target_compile_definitions(https_server PUBLIC WITH_CPPHTTPLIB_LIB)
  target_link_libraries(https_server PRIVATE os log httplib_wrapper)
endif()
