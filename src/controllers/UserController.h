#pragma once
#include <drogon/HttpController.h>

class UserController : public drogon::HttpController<UserController> {
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(UserController::me, "/api/me", drogon::Get, "AuthFilter");
    ADD_METHOD_TO(UserController::updateMe, "/api/me", drogon::Patch, "AuthFilter");
    ADD_METHOD_TO(UserController::changePassword, "/api/me/password", drogon::Patch, "AuthFilter");
    ADD_METHOD_TO(UserController::listUsers, "/api/users", drogon::Get, "AuthFilter");
    ADD_METHOD_TO(UserController::getUserById, "/api/users/{1}", drogon::Get, "AuthFilter");
    ADD_METHOD_TO(UserController::updateUserById, "/api/users/{1}", drogon::Patch, "AuthFilter");
    ADD_METHOD_TO(UserController::deleteUserById, "/api/users/{1}", drogon::Delete, "AuthFilter");
    ADD_METHOD_TO(UserController::bulkInvite, "/api/users/bulk-invite", drogon::Post, "AuthFilter");
    METHOD_LIST_END

    void me(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void updateMe(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void changePassword(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void listUsers(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void getUserById(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback, const std::string& id);
    void updateUserById(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback, const std::string& id);
    void deleteUserById(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback, const std::string& id);
    void bulkInvite(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
};
