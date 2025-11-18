cmake_minimum_required(VERSION 3.25)
project(n-api-without-gyp)

set(CMAKE_BUILD_TYPE "Debug")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_SHARED_LINKER_FLAGS "-undefined dynamic_lookup")

add_definitions(-DNAPI_VERSION=3)

include_directories(~/.nvm/versions/node/v24.11.0/include/node/)
file(GLOB SOURCE_FILES "hello.c")
add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES})
set_target_properties(${PROJECT_NAME}
  PROPERTIES
    PREFIX ""
    SUFFIX ".node")

add_library(callbacks SHARED callbacks.c)
set_target_properties(callbacks
  PROPERTIES
    PREFIX ""
    SUFFIX ".node")

add_library(func-creation SHARED func-creation.c)
set_target_properties(func-creation
  PROPERTIES
    PREFIX ""
    SUFFIX ".node")
