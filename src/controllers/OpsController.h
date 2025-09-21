#pragma once
#include <drogon/HttpController.h>

class OpsController : public drogon::HttpController<OpsController> {
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(OpsController::auditLogs, "/api/audit-logs", drogon::Get, "AuthFilter");
    ADD_METHOD_TO(OpsController::metrics, "/api/metrics", drogon::Get, "AuthFilter");
    ADD_METHOD_TO(OpsController::flushCache, "/api/admin/cache/flush", drogon::Post, "AuthFilter");
    METHOD_LIST_END

    void auditLogs(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void metrics(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void flushCache(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
};
