#pragma once
#include <drogon/HttpController.h>

class AuthController : public drogon::HttpController<AuthController> {
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(AuthController::registerUser, "/api/auth/register", drogon::Post);
    ADD_METHOD_TO(AuthController::login, "/api/auth/login", drogon::Post);
    ADD_METHOD_TO(AuthController::logout, "/api/auth/logout", drogon::Post, "AuthFilter");
    ADD_METHOD_TO(AuthController::refresh, "/api/auth/refresh", drogon::Post);
    ADD_METHOD_TO(AuthController::forgotPassword, "/api/auth/forgot-password", drogon::Post);
    ADD_METHOD_TO(AuthController::resetPassword, "/api/auth/reset-password", drogon::Post);
    ADD_METHOD_TO(AuthController::verifyEmail, "/api/auth/verify-email", drogon::Post);
    ADD_METHOD_TO(AuthController::jwks, "/api/auth/jwks", drogon::Get);
    ADD_METHOD_TO(AuthController::startTotpEnrollment, "/api/auth/totp/enable", drogon::Post, "AuthFilter");
    ADD_METHOD_TO(AuthController::verifyTotpEnrollment, "/api/auth/totp/verify", drogon::Post, "AuthFilter");
    ADD_METHOD_TO(AuthController::disableTotp, "/api/auth/totp/disable", drogon::Post, "AuthFilter");
    ADD_METHOD_TO(AuthController::generateBackupCodes, "/api/auth/backup-codes", drogon::Post, "AuthFilter");
    METHOD_LIST_END

    void registerUser(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void login(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void logout(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void refresh(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void forgotPassword(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void resetPassword(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void verifyEmail(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void jwks(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void startTotpEnrollment(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void verifyTotpEnrollment(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void disableTotp(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void generateBackupCodes(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
};
