#pragma once
#include <drogon/HttpController.h>

class UserController : public drogon::HttpController<UserController> {
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(UserController::me, "/api/me", drogon::Get, "AuthFilter");
    ADD_METHOD_TO(UserController::listUsers, "/api/users", drogon::Get, "AuthFilter");
    METHOD_LIST_END

    void me(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void listUsers(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
};
