#pragma once
#include <drogon/HttpController.h>

class NotificationController : public drogon::HttpController<NotificationController> {
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(NotificationController::listNotifications, "/api/notifications", drogon::Get, "AuthFilter");
    ADD_METHOD_TO(NotificationController::markRead, "/api/notifications/mark-read", drogon::Post, "AuthFilter");
    ADD_METHOD_TO(NotificationController::markAllRead, "/api/notifications/mark-all-read", drogon::Post, "AuthFilter");
    METHOD_LIST_END

    void listNotifications(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void markRead(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void markAllRead(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
};
