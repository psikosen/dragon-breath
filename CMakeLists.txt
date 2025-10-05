
cmake_minimum_required(VERSION 3.16)
project(drgn_surreal_starter LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT MYSQL_INCLUDE_DIRS)
    set(MYSQL_INCLUDE_DIRS "/usr/include/mysql" CACHE PATH "MySQL include dir")
endif()
if(NOT MYSQL_LIBRARIES)
    set(MYSQL_LIBRARIES "/usr/lib/x86_64-linux-gnu/libmysqlclient.so" CACHE FILEPATH "MySQL client library")
endif()


find_package(Drogon CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Protobuf REQUIRED)
find_package(c-ares CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)
find_program(GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin REQUIRED)

set(PROTO_SRC ${CMAKE_CURRENT_SOURCE_DIR}/proto/user.proto)
set(GRPC_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${GRPC_GENERATED_DIR})

add_custom_command(
    OUTPUT
        ${GRPC_GENERATED_DIR}/user.pb.cc
        ${GRPC_GENERATED_DIR}/user.pb.h
        ${GRPC_GENERATED_DIR}/user.grpc.pb.cc
        ${GRPC_GENERATED_DIR}/user.grpc.pb.h
    COMMAND ${Protobuf_PROTOC_EXECUTABLE}
    ARGS --proto_path=${CMAKE_CURRENT_SOURCE_DIR}/proto
         --cpp_out=${GRPC_GENERATED_DIR}
         --grpc_out=${GRPC_GENERATED_DIR}
         --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN_EXECUTABLE}
         ${PROTO_SRC}
    DEPENDS ${PROTO_SRC}
    COMMENT "Generating gRPC sources"
    VERBATIM
)

add_custom_target(generate_grpc_user
    DEPENDS
        ${GRPC_GENERATED_DIR}/user.pb.cc
        ${GRPC_GENERATED_DIR}/user.pb.h
        ${GRPC_GENERATED_DIR}/user.grpc.pb.cc
        ${GRPC_GENERATED_DIR}/user.grpc.pb.h
)


add_library(grpc_user_proto STATIC
    ${GRPC_GENERATED_DIR}/user.pb.cc
    ${GRPC_GENERATED_DIR}/user.grpc.pb.cc
)
add_dependencies(grpc_user_proto generate_grpc_user)
target_include_directories(grpc_user_proto PUBLIC ${GRPC_GENERATED_DIR})
target_link_libraries(grpc_user_proto PUBLIC gRPC::grpc++ protobuf::libprotobuf)

add_executable(drgn_surreal
    src/main.cc
    src/db/SurrealClient.cc
    src/filters/AuthFilter.cc
    src/controllers/AuthController.cc
    src/controllers/UserController.cc
    src/grpc/UserServiceImpl.cc
)
add_dependencies(drgn_surreal generate_grpc_user)

target_include_directories(drgn_surreal
    PRIVATE
        ${OPENSSL_INCLUDE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(drgn_surreal PRIVATE Drogon::Drogon OpenSSL::SSL OpenSSL::Crypto grpc_user_proto)

if(APPLE)
    set_target_properties(drgn_surreal PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "@executable_path/../lib"
    )
endif()
