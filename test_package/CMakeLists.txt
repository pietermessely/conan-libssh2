cmake_minimum_required(VERSION 3.1)
project(example)


include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()


add_executable(${PROJECT_NAME} example.cpp)
target_link_libraries(${PROJECT_NAME} ${CONAN_LIBS})
