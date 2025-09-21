#pragma once
#include <drogon/HttpController.h>

class ApiKeyController : public drogon::HttpController<ApiKeyController> {
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(ApiKeyController::listKeys, "/api/api-keys", drogon::Get, "AuthFilter");
    ADD_METHOD_TO(ApiKeyController::createKey, "/api/api-keys", drogon::Post, "AuthFilter");
    ADD_METHOD_TO(ApiKeyController::deleteKey, "/api/api-keys/{1}", drogon::Delete, "AuthFilter");
    ADD_METHOD_TO(ApiKeyController::rotateKey, "/api/api-keys/{1}/rotate", drogon::Post, "AuthFilter");
    METHOD_LIST_END

    void listKeys(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void createKey(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void deleteKey(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback, const std::string& id);
    void rotateKey(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback, const std::string& id);
};
