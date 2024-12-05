cmake_minimum_required(VERSION 3.15)

project(dynamic_key C)
add_executable(dynamic_key main.c)

if(NOT TARGET encrypt_section)
  add_subdirectory("../encrypt_section" "${CMAKE_CURRENT_BINARY_DIR}/encrypt_section")
endif()

add_dependencies(dynamic_key encrypt_section)

add_custom_command(TARGET dynamic_key
  POST_BUILD
  COMMAND encrypt_section ARGS -b "$<TARGET_FILE:dynamic_key>" -x .encc -d .encd -k "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/key.txt")
