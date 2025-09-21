#pragma once
#include <drogon/HttpController.h>

class WebhookController : public drogon::HttpController<WebhookController> {
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(WebhookController::listWebhooks, "/api/webhooks", drogon::Get, "AuthFilter");
    ADD_METHOD_TO(WebhookController::createWebhook, "/api/webhooks", drogon::Post, "AuthFilter");
    ADD_METHOD_TO(WebhookController::getWebhook, "/api/webhooks/{1}", drogon::Get, "AuthFilter");
    ADD_METHOD_TO(WebhookController::updateWebhook, "/api/webhooks/{1}", drogon::Patch, "AuthFilter");
    ADD_METHOD_TO(WebhookController::deleteWebhook, "/api/webhooks/{1}", drogon::Delete, "AuthFilter");
    ADD_METHOD_TO(WebhookController::testWebhook, "/api/webhooks/{1}/test", drogon::Post, "AuthFilter");
    METHOD_LIST_END

    void listWebhooks(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void createWebhook(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void getWebhook(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback, const std::string& id);
    void updateWebhook(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback, const std::string& id);
    void deleteWebhook(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback, const std::string& id);
    void testWebhook(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback, const std::string& id);
};
