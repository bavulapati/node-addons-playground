cmake_minimum_required(VERSION 3.25)
project(n-api-explore)

message(STATUS "CMAKE_JS_INC: ${CMAKE_JS_INC}")
message(STATUS "CMAKE_JS_LIB: ${CMAKE_JS_LIB}")
message(STATUS "CMAKE_JS_SRC: ${CMAKE_JS_SRC}")
set(CMAKE_BUILD_TYPE "Debug")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include_directories(${CMAKE_JS_INC})
file(GLOB SOURCE_FILES "hello.c")
add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES} ${CMAKE_JS_SRC})
set_target_properties(${PROJECT_NAME}
  PROPERTIES
    PREFIX ""
    SUFFIX ".node")
target_link_libraries(${PROJECT_NAME} ${CMAKE_JS_LIB})

add_definitions(-DNAPI_VERSION=3)
