project(privwrite C)

cmake_minimum_required(VERSION 3.0.2)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_compile_options(-Wall -std=gnu99)

include_directories(${CMAKE_SOURCE_DIR}/include)
link_directories(${CMAKE_SOURCE_DIR}/lib)

set(PROJECT_VERSION "0.1.0")
set(SRC main.c)

add_definitions(-DPROJECT_VERSION="${PROJECT_VERSION}")
add_definitions(-DPROJECT_NAME="${PROJECT_NAME}")

add_executable(${PROJECT_NAME} ${SRC})
target_link_libraries(${PROJECT_NAME} s96at)
target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES})
