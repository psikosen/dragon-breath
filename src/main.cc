
#include <drogon/drogon.h>
#include <cstdlib>
#include <memory>
#include <string>
#include <thread>

#include <grpcpp/grpcpp.h>

#include "grpc/UserServiceImpl.h"
#include "utils/logging.hpp"

int main(int argc, char* argv[]) {
    using namespace drogon;

    std::string grpcAddress = "0.0.0.0:50051";
    if (const char* envAddr = std::getenv("GRPC_LISTEN_ADDR")) {
        if (*envAddr != '\0') {
            grpcAddress = envAddr;
        }
    }

    UserServiceImpl userService;
    grpc::ServerBuilder grpcBuilder;
    grpcBuilder.AddListeningPort(grpcAddress, grpc::InsecureServerCredentials());
    grpcBuilder.RegisterService(&userService);
    std::unique_ptr<grpc::Server> grpcServer(grpcBuilder.BuildAndStart());
    if (!grpcServer) {
        logging::error("main.cc", "main", "main", "grpc", __LINE__,
                       "Failed to start gRPC server on " + grpcAddress, "UserService.GetUser");
        return EXIT_FAILURE;
    }

    logging::info("main.cc", "main", "main", "grpc", __LINE__,
                  "gRPC server listening on " + grpcAddress, "UserService.GetUser");
    std::thread grpcThread([serverPtr = grpcServer.get()]() {
        serverPtr->Wait();
    });

    app().addListener("0.0.0.0", 8080);

    app().registerPostHandlingAdvice([](const HttpRequestPtr& req, const HttpResponsePtr& resp){
        resp->addHeader("Access-Control-Allow-Origin", "*");
        resp->addHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
        resp->addHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    });

    app().registerHandler("/{path}", [](const HttpRequestPtr&, std::function<void (const HttpResponsePtr &)> &&callback){
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k204NoContent);
        callback(resp);
    }, {drogon::Options});

    LOG_INFO << "Starting HTTP server...";
    app().run();

    grpcServer->Shutdown();
    if (grpcThread.joinable()) {
        grpcThread.join();
    }
    return 0;
}
