file(GLOB_RECURSE src RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/../../libafanasy/*.cpp")
file(GLOB_RECURSE inc RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/../../libafanasy/*.h")
list(FILTER src EXCLUDE REGEX ".*/tests/.*")
list(FILTER inc EXCLUDE REGEX ".*/tests/.*")

add_library(afanasy ${src} ${inc})
if(UNIX AND NOT APPLE)
   set_target_properties(afanasy PROPERTIES COMPILE_FLAGS "-fPIC $ENV{AF_ADD_CFLAGS}")
endif(UNIX AND NOT APPLE)
target_link_libraries(afanasy ${PYTHON_LIBRARIES})

add_definitions(-DCGRU_REVISION=$ENV{CGRU_REVISION})
add_definitions(-DCGRU_VERSION=$ENV{CGRU_VERSION})

# Add test for Msg memory leaks
add_executable(test_msg_allocatebuffer_simple_boundary
    "${CMAKE_CURRENT_SOURCE_DIR}/../../libafanasy/tests/test_msg_allocatebuffer_simple_boundary.cpp"
)
target_link_libraries(test_msg_allocatebuffer_simple_boundary afanasy)
add_test(NAME AllocateBufferSimpleBoundary COMMAND test_msg_allocatebuffer_simple_boundary)

add_executable(test_msg_allocatebuffer_negative_copy
    "${CMAKE_CURRENT_SOURCE_DIR}/../../libafanasy/tests/test_msg_allocatebuffer_negative_copy.cpp"
)
target_link_libraries(test_msg_allocatebuffer_negative_copy afanasy)
add_test(NAME MsgMemoryTest COMMAND test_msg_allocatebuffer_negative_copy)
