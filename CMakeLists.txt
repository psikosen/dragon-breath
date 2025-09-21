cmake_minimum_required(VERSION 3.16)
project(drgn_surreal_starter LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Drogon (installed via package manager or built from source)
find_package(Drogon CONFIG REQUIRED)
# OpenSSL for HMAC/PBKDF2
find_package(OpenSSL REQUIRED)

add_executable(drgn_surreal
    src/main.cc
    src/db/SurrealClient.cc
    src/filters/AuthFilter.cc
    src/controllers/AuthController.cc
    src/controllers/UserController.cc
    src/controllers/RbacController.cc
    src/controllers/ProjectController.cc
    src/controllers/OpsController.cc
    src/controllers/SessionController.cc
    src/controllers/ApiKeyController.cc
    src/controllers/WebhookController.cc
    src/controllers/NotificationController.cc
    src/controllers/FileController.cc
    src/controllers/SearchController.cc
    src/controllers/TaskController.cc
    src/controllers/HealthController.cc
)

target_include_directories(drgn_surreal PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(drgn_surreal PRIVATE Drogon::Drogon OpenSSL::SSL OpenSSL::Crypto)

# On macOS, rpath for Drogon if installed via brew/vcpkg
if(APPLE)
    set_target_properties(drgn_surreal PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "@executable_path/../lib"
    )
endif()
