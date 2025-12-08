cmake_minimum_required(VERSION 3.15...3.31)
project(tcp)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_definitions(NAPI_VERSION=4)
# set(CMAKE_BUILD_TYPE "Debug")

file(GLOB SOURCE_FILES "client.c")

add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES} ${CMAKE_JS_SRC})

set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")
# Define DEBUG macro only for debug builds
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  # target_compile_options(${PROJECT_NAME} PUBLIC -fsanitize=address -fno-omit-frame-pointer)
  # target_link_options(${PROJECT_NAME} PUBLIC -fsanitize=address)
  target_compile_definitions(${PROJECT_NAME} PUBLIC DEBUG)
  target_compile_definitions(${PROJECT_NAME} PUBLIC MEMORY_DEBUG)
endif()

set(CMAKE_JS_NODE_INC ~/.cmake-js/node-arm64/v24.11.0/include/node/)

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_JS_INC})
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_JS_NODE_INC})
target_link_libraries(${PROJECT_NAME} PRIVATE ${CMAKE_JS_LIB})
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_17)

if(MSVC AND CMAKE_JS_NODELIB_DEF AND CMAKE_JS_NODELIB_TARGET)
  # Generate node.lib
  execute_process(COMMAND ${CMAKE_AR} /def:${CMAKE_JS_NODELIB_DEF} /out:${CMAKE_JS_NODELIB_TARGET} ${CMAKE_STATIC_LINKER_FLAGS})
endif()

message(STATUS  "CMAKE_JS_INC ${CMAKE_JS_INC}")

