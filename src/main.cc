#include <drogon/drogon.h>
#include <cstdlib>
#include <string>

int main(int argc, char* argv[]) {
    using namespace drogon;

    // Load config if provided via --config
    app().addListener("0.0.0.0", 8080);

    // Basic CORS for API
    app().registerPostHandlingAdvice([](const HttpRequestPtr& req, const HttpResponsePtr& resp){
        resp->addHeader("Access-Control-Allow-Origin", "*");
        resp->addHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
        resp->addHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    });

    // Simple OPTIONS responder
    app().registerHandler("/{path}", [](const HttpRequestPtr&, std::function<void (const HttpResponsePtr &)> &&callback){
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k204NoContent);
        callback(resp);
    }, {drogon::Options});

    LOG_INFO << "Starting server...";
    app().run();
    return 0;
}
