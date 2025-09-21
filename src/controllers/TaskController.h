#pragma once
#include <drogon/HttpController.h>

class TaskController : public drogon::HttpController<TaskController> {
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(TaskController::listTasks, "/api/tasks", drogon::Get, "AuthFilter");
    ADD_METHOD_TO(TaskController::createTask, "/api/tasks", drogon::Post, "AuthFilter");
    ADD_METHOD_TO(TaskController::updateTask, "/api/tasks/{1}", drogon::Patch, "AuthFilter");
    ADD_METHOD_TO(TaskController::deleteTask, "/api/tasks/{1}", drogon::Delete, "AuthFilter");
    ADD_METHOD_TO(TaskController::updateAssignees, "/api/tasks/{1}/assignees", drogon::Post, "AuthFilter");
    ADD_METHOD_TO(TaskController::updateStatus, "/api/tasks/{1}/status", drogon::Post, "AuthFilter");
    METHOD_LIST_END

    void listTasks(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void createTask(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void updateTask(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback, const std::string& id);
    void deleteTask(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback, const std::string& id);
    void updateAssignees(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback, const std::string& id);
    void updateStatus(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback, const std::string& id);
};
