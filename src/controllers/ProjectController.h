#pragma once
#include <drogon/HttpController.h>

class ProjectController : public drogon::HttpController<ProjectController> {
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(ProjectController::listProjects, "/api/projects", drogon::Get, "AuthFilter");
    ADD_METHOD_TO(ProjectController::createProject, "/api/projects", drogon::Post, "AuthFilter");
    ADD_METHOD_TO(ProjectController::getProject, "/api/projects/{1}", drogon::Get, "AuthFilter");
    ADD_METHOD_TO(ProjectController::updateProject, "/api/projects/{1}", drogon::Patch, "AuthFilter");
    ADD_METHOD_TO(ProjectController::archiveProject, "/api/projects/{1}", drogon::Delete, "AuthFilter");
    METHOD_LIST_END

    void listProjects(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void createProject(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void getProject(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback, const std::string& id);
    void updateProject(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback, const std::string& id);
    void archiveProject(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback, const std::string& id);
};
