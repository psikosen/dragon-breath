#include "RbacController.h"
#include <drogon/drogon.h>
#include "../db/SurrealClient.h"
#include "../utils/logging.hpp"
#include <sstream>
#include <algorithm>
#include <stdexcept>

using namespace drogon;

namespace {
bool isAdmin(const Json::Value& claims) {
    return claims.get("role","user").asString() == "admin";
}

Json::Value ensureRole(SurrealClient& db, const std::string& id) {
    auto role = db.selectById("role", id);
    if (role.isNull()) {
        throw std::runtime_error("role not found");
    }
    return role;
}

Json::Value ensureTeam(SurrealClient& db, const std::string& id) {
    auto team = db.selectById("team", id);
    if (team.isNull()) {
        throw std::runtime_error("team not found");
    }
    return team;
}

Json::Value ensureOrg(SurrealClient& db, const std::string& id) {
    auto org = db.selectById("organization", id);
    if (org.isNull()) {
        throw std::runtime_error("org not found");
    }
    return org;
}

void ensureRoleSeeded(SurrealClient& db) {
    auto res = db.exec("SELECT * FROM role LIMIT 1;");
    bool empty = true;
    if (res.isArray() && res.size() > 0 && res[0]["result"].isArray() && res[0]["result"].size() > 0) {
        empty = false;
    }
    if (!empty) return;
    Json::Value admin;
    admin["name"] = "admin";
    admin["permissions"] = Json::Value(Json::arrayValue);
    admin["permissions"].append("*");
    admin["description"] = "Administrator";
    db.createRecord("role", admin);
    Json::Value member;
    member["name"] = "member";
    member["permissions"] = Json::Value(Json::arrayValue);
    member["permissions"].append("projects:read");
    member["permissions"].append("tasks:read");
    member["description"] = "Standard user";
    db.createRecord("role", member);
}

bool isOrgCollaborator(const Json::Value& org, const std::string& userId) {
    if (org.get("owner", "").asString() == userId) return true;
    auto members = org["members"];
    if (members.isArray()) {
        for (const auto& entry : members) {
            if (entry.asString() == userId) return true;
        }
    }
    return false;
}

void ensureOrgMembership(SurrealClient& db, const std::string& orgId, const std::string& userId) {
    auto org = ensureOrg(db, orgId);
    if (!isOrgCollaborator(org, userId)) {
        throw std::runtime_error("forbidden");
    }
}

void updateOrgMembers(SurrealClient& db, const std::string& orgId, const std::string& userId) {
    auto org = ensureOrg(db, orgId);
    auto members = org["members"];
    bool exists = false;
    Json::Value updated(Json::arrayValue);
    if (members.isArray()) {
        for (const auto& entry : members) {
            if (entry.asString() == userId) {
                exists = true;
            }
            updated.append(entry);
        }
    }
    if (!exists) {
        updated.append(userId);
        Json::Value merge;
        merge["members"] = updated;
        db.mergeRecord("organization", orgId, merge);
    }
}

void writeAudit(SurrealClient& db, const std::string& event, const std::string& actor, const Json::Value& metadata = Json::Value()) {
    try {
        Json::Value rec;
        if (!actor.empty()) rec["actor"] = actor;
        rec["event"] = event;
        if (!metadata.isNull()) rec["metadata"] = metadata;
        db.createRecord("audit_log", rec);
    } catch (const std::exception& e) {
        logging::error(__FILE__, "RbacController", __func__, "audit", __LINE__, "audit write failed", "NONE", e.what(), "none");
    }
}

} // namespace

void RbacController::listRoles(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "RbacController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    if (!isAdmin(claims)) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
        resp->setStatusCode(k403Forbidden);
        return callback(resp);
    }
    try {
        SurrealClient db;
        ensureRoleSeeded(db);
        auto res = db.exec("SELECT * FROM role ORDER BY name ASC;");
        Json::Value out(Json::objectValue);
        out["roles"] = Json::Value(Json::arrayValue);
        if (res.isArray() && res.size() > 0) {
            for (const auto& row : res[0]["result"]) {
                out["roles"].append(row);
            }
        }
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "rbac", __LINE__, "list roles failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","query failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void RbacController::updateRolePermissions(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& roleId) {
    constexpr auto className = "RbacController";
    auto attrs = req->getAttributes();
    if (!isAdmin(attrs->get<Json::Value>("claims"))) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
        resp->setStatusCode(k403Forbidden);
        return callback(resp);
    }
    auto json = req->getJsonObject();
    if (!json || !json->isMember("permissions") || !(*json)["permissions"].isArray()) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","permissions array required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    try {
        SurrealClient db;
        ensureRole(db, roleId);
        Json::Value update;
        update["permissions"] = (*json)["permissions"];
        auto role = db.mergeRecord("role", roleId, update);
        Json::Value out;
        out["role"] = role;
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "rbac", __LINE__, "update permissions failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","update failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void RbacController::listOrganizations(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "RbacController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto userId = claims.get("sub", "").asString();
    try {
        SurrealClient db;
        std::stringstream ss;
        ss << "SELECT * FROM organization WHERE owner = '" << drogon::utils::escapeHtml(userId) << "' OR array::contains(members, '" << drogon::utils::escapeHtml(userId) << "') ORDER BY created_at DESC;";
        auto res = db.exec(ss.str());
        Json::Value out;
        out["organizations"] = Json::Value(Json::arrayValue);
        if (res.isArray() && res.size() > 0) {
            for (const auto& row : res[0]["result"]) {
                out["organizations"].append(row);
            }
        }
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "rbac", __LINE__, "list orgs failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","query failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void RbacController::createTeam(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "RbacController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto json = req->getJsonObject();
    if (!json || !json->isMember("name")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","name required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    auto orgId = json->get("org", "").asString();
    auto name = (*json)["name"].asString();
    auto description = json->get("description", "").asString();
    try {
        SurrealClient db;
        if (!orgId.empty()) {
            ensureOrgMembership(db, orgId, claims.get("sub", "").asString());
        }
        Json::Value rec;
        rec["org"] = orgId;
        rec["name"] = name;
        if (!description.empty()) rec["description"] = description;
        rec["created_by"] = claims.get("sub", "").asString();
        auto team = db.createRecord("team", rec);
        if (!orgId.empty()) {
            updateOrgMembers(db, orgId, claims.get("sub", "").asString());
        }
        Json::Value out;
        out["team"] = team;
        writeAudit(db, "team.created", claims.get("sub", "").asString(), Json::Value{{"team_id", team["id"].asString()}});
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "rbac", __LINE__, "create team failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","create failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void RbacController::addTeamMember(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& teamId) {
    constexpr auto className = "RbacController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto json = req->getJsonObject();
    if (!json || !json->isMember("user_id")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","user_id required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    auto targetUser = (*json)["user_id"].asString();
    auto role = json->get("role", "member").asString();
    try {
        SurrealClient db;
        auto team = ensureTeam(db, teamId);
        if (!isAdmin(claims) && team.get("created_by", "").asString() != claims.get("sub", "").asString()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
            resp->setStatusCode(k403Forbidden);
            return callback(resp);
        }
        Json::Value rec;
        rec["team"] = teamId;
        rec["user"] = targetUser;
        rec["role"] = role;
        auto member = db.createRecord("team_member", rec);
        auto orgId = team.get("org", "").asString();
        if (!orgId.empty()) {
            updateOrgMembers(db, orgId, targetUser);
        }
        Json::Value out;
        out["member"] = member;
        writeAudit(db, "team.member_added", claims.get("sub", "").asString(), Json::Value{{"team_id", teamId}, {"user_id", targetUser}});
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "rbac", __LINE__, "add member failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","add failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void RbacController::removeTeamMember(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& teamId, const std::string& userId) {
    constexpr auto className = "RbacController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    try {
        SurrealClient db;
        auto team = ensureTeam(db, teamId);
        if (!isAdmin(claims) && team.get("created_by", "").asString() != claims.get("sub", "").asString()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
            resp->setStatusCode(k403Forbidden);
            return callback(resp);
        }
        std::stringstream ss;
        ss << "DELETE team_member WHERE team = '" << drogon::utils::escapeHtml(teamId) << "' AND user = '" << drogon::utils::escapeHtml(userId) << "';";
        db.exec(ss.str());
        writeAudit(db, "team.member_removed", claims.get("sub", "").asString(), Json::Value{{"team_id", teamId}, {"user_id", userId}});
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k204NoContent);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "rbac", __LINE__, "remove member failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","remove failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}
