cmake_minimum_required(VERSION 3.15)

project(custom_loader_payload C)
add_executable(custom_loader_payload main.c)

if(NOT TARGET binobj)
  add_subdirectory("../binobj" "${CMAKE_CURRENT_BINARY_DIR}/binobj")
endif()

if(NOT TARGET encrypt_section)
  add_subdirectory("../encrypt_section" "${CMAKE_CURRENT_BINARY_DIR}/encrypt_section")
endif()

add_dependencies(custom_loader_payload encrypt_section)

add_custom_command(TARGET custom_loader_payload
  POST_BUILD
  COMMAND encrypt_section ARGS -b "$<TARGET_FILE:custom_loader_payload>" -x .encc -d .encd -H "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/custom_loader_payload.h")

project(custom_loader C)
add_executable(custom_loader loader.c)
add_dependencies(custom_loader custom_loader_payload)

add_custom_command(TARGET custom_loader
  PRE_BUILD
  COMMAND binobj ARGS SHEEP_LOADER 1 "$<TARGET_FILE:custom_loader_payload>" "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/sheep_loader.obj")

target_link_libraries(custom_loader "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/sheep_loader.obj")
file(SIZE "$<TARGET_FILE:custom_loader_payload>" CUSTOM_LOADER_PAYLOAD_SIZE)
target_compile_definitions(custom_loader PUBLIC SHEEP_LOADER_SIZE=${CUSTOM_LOADER_PAYLOAD_SIZE})
