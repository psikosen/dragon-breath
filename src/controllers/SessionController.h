#pragma once
#include <drogon/HttpController.h>

class SessionController : public drogon::HttpController<SessionController> {
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(SessionController::listSessions, "/api/sessions", drogon::Get, "AuthFilter");
    ADD_METHOD_TO(SessionController::revokeSession, "/api/sessions/{1}", drogon::Delete, "AuthFilter");
    METHOD_LIST_END

    void listSessions(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void revokeSession(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback, const std::string& id);
};
