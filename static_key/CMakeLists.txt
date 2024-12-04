cmake_minimum_required(VERSION 3.15)

project(static_key C)
add_executable(static_key main.c)

if(NOT TARGET encrypt_section)
  add_subdirectory("../encrypt_section" "${CMAKE_CURRENT_BINARY_DIR}/encrypt_section")
endif()

add_dependencies(static_key encrypt_section)

add_custom_command(TARGET static_key
  POST_BUILD
  COMMAND encrypt_section ARGS -b "$<TARGET_FILE:static_key>" -x .etext -d .edata -s .tls1)
