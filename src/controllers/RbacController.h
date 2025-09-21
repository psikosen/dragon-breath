#pragma once
#include <drogon/HttpController.h>

class RbacController : public drogon::HttpController<RbacController> {
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(RbacController::listRoles, "/api/roles", drogon::Get, "AuthFilter");
    ADD_METHOD_TO(RbacController::updateRolePermissions, "/api/roles/{1}/permissions", drogon::Patch, "AuthFilter");
    ADD_METHOD_TO(RbacController::listOrganizations, "/api/orgs", drogon::Get, "AuthFilter");
    ADD_METHOD_TO(RbacController::createTeam, "/api/teams", drogon::Post, "AuthFilter");
    ADD_METHOD_TO(RbacController::addTeamMember, "/api/teams/{1}/members", drogon::Post, "AuthFilter");
    ADD_METHOD_TO(RbacController::removeTeamMember, "/api/teams/{1}/members/{2}", drogon::Delete, "AuthFilter");
    METHOD_LIST_END

    void listRoles(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void updateRolePermissions(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback, const std::string& roleId);
    void listOrganizations(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void createTeam(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void addTeamMember(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback, const std::string& teamId);
    void removeTeamMember(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback, const std::string& teamId, const std::string& userId);
};
