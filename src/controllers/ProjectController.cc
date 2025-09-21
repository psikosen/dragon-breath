#include "ProjectController.h"
#include <drogon/drogon.h>
#include "../db/SurrealClient.h"
#include "../utils/logging.hpp"
#include <sstream>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <stdexcept>

using namespace drogon;

namespace {
bool isAdmin(const Json::Value& claims) {
    return claims.get("role","user").asString() == "admin";
}

Json::Value ensureProject(SurrealClient& db, const std::string& id) {
    auto project = db.selectById("project", id);
    if (project.isNull()) {
        throw std::runtime_error("project not found");
    }
    return project;
}

bool canAccessProject(const Json::Value& project, const Json::Value& claims) {
    if (isAdmin(claims)) return true;
    auto owner = project.get("created_by", "").asString();
    if (owner == claims.get("sub", "").asString()) return true;
    return false;
}

std::string isoNow() {
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *gmtime(&tt);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

void writeAudit(SurrealClient& db, const std::string& event, const std::string& actor, const Json::Value& metadata = Json::Value()) {
    try {
        Json::Value rec;
        if (!actor.empty()) rec["actor"] = actor;
        rec["event"] = event;
        if (!metadata.isNull()) rec["metadata"] = metadata;
        db.createRecord("audit_log", rec);
    } catch (const std::exception& e) {
        logging::error(__FILE__, "ProjectController", __func__, "audit", __LINE__, "audit write failed", "NONE", e.what(), "none");
    }
}

} // namespace

void ProjectController::listProjects(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "ProjectController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto userId = claims.get("sub", "").asString();
    auto status = req->getParameter("status");
    try {
        SurrealClient db;
        std::stringstream ss;
        ss << "SELECT * FROM project WHERE ";
        if (isAdmin(claims)) {
            ss << "true";
        } else {
            ss << "created_by = '" << drogon::utils::escapeHtml(userId) << "'";
        }
        if (!status.empty()) {
            ss << " AND status = '" << drogon::utils::escapeHtml(status) << "'";
        }
        ss << " ORDER BY created_at DESC LIMIT 100;";
        auto res = db.exec(ss.str());
        Json::Value out;
        out["projects"] = Json::Value(Json::arrayValue);
        if (res.isArray() && res.size() > 0) {
            for (const auto& row : res[0]["result"]) {
                out["projects"].append(row);
            }
        }
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "projects", __LINE__, "list failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","query failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void ProjectController::createProject(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "ProjectController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto json = req->getJsonObject();
    if (!json || !json->isMember("name")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","name required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    try {
        SurrealClient db;
        Json::Value rec;
        rec["name"] = (*json)["name"].asString();
        if (json->isMember("description")) rec["description"] = (*json)["description"];
        if (json->isMember("org")) rec["org"] = (*json)["org"];
        if (json->isMember("metadata")) rec["metadata"] = (*json)["metadata"];
        rec["created_by"] = claims.get("sub", "").asString();
        auto project = db.createRecord("project", rec);
        Json::Value out;
        out["project"] = project;
        writeAudit(db, "project.created", claims.get("sub", "").asString(), Json::Value{{"project_id", project["id"].asString()}});
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "projects", __LINE__, "create failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","create failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void ProjectController::getProject(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& id) {
    constexpr auto className = "ProjectController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    try {
        SurrealClient db;
        auto project = ensureProject(db, id);
        if (!canAccessProject(project, claims)) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
            resp->setStatusCode(k403Forbidden);
            return callback(resp);
        }
        Json::Value out;
        out["project"] = project;
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","not found"}});
        resp->setStatusCode(k404NotFound);
        callback(resp);
    }
}

void ProjectController::updateProject(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& id) {
    constexpr auto className = "ProjectController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto json = req->getJsonObject();
    if (!json) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","body required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    try {
        SurrealClient db;
        auto project = ensureProject(db, id);
        if (!canAccessProject(project, claims)) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
            resp->setStatusCode(k403Forbidden);
            return callback(resp);
        }
        Json::Value update(Json::objectValue);
        if (json->isMember("name")) update["name"] = (*json)["name"];
        if (json->isMember("description")) update["description"] = (*json)["description"];
        if (json->isMember("status")) update["status"] = (*json)["status"];
        if (json->isMember("metadata")) update["metadata"] = (*json)["metadata"];
        if (update.getMemberNames().empty()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","no fields"}});
            resp->setStatusCode(k400BadRequest);
            return callback(resp);
        }
        auto updated = db.mergeRecord("project", id, update);
        Json::Value out;
        out["project"] = updated;
        writeAudit(db, "project.updated", claims.get("sub", "").asString(), Json::Value{{"project_id", id}});
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "projects", __LINE__, "update failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","update failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void ProjectController::archiveProject(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& id) {
    constexpr auto className = "ProjectController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    try {
        SurrealClient db;
        auto project = ensureProject(db, id);
        if (!canAccessProject(project, claims)) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
            resp->setStatusCode(k403Forbidden);
            return callback(resp);
        }
        Json::Value update;
        update["archived_at"] = isoNow();
        update["status"] = "archived";
        db.mergeRecord("project", id, update);
        writeAudit(db, "project.archived", claims.get("sub", "").asString(), Json::Value{{"project_id", id}});
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k204NoContent);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "projects", __LINE__, "archive failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","archive failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}
