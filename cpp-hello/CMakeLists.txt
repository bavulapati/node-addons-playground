cmake_minimum_required(VERSION 3.25)
project(hello)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_BUILD_TYPE "Debug")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_SHARED_LINKER_FLAGS "-undefined dynamic_lookup")

include_directories(~/source/nodejs/node/build/usr/local/include/node/)
file(GLOB SOURCE_FILES "hello.cc")
add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES})
set_target_properties(${PROJECT_NAME}
  PROPERTIES
    PREFIX ""
    SUFFIX ".node")

add_definitions(-DNAPI_VERSION=3)
