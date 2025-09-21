#include "TaskController.h"
#include <drogon/drogon.h>
#include "../db/SurrealClient.h"
#include "../utils/logging.hpp"
#include <sstream>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <vector>
#include <stdexcept>

using namespace drogon;

namespace {
bool isAdmin(const Json::Value& claims) {
    return claims.get("role","user").asString() == "admin";
}

std::string isoNow() {
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *gmtime(&tt);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

Json::Value ensureTask(SurrealClient& db, const std::string& id) {
    auto task = db.selectById("task", id);
    if (task.isNull()) {
        throw std::runtime_error("task not found");
    }
    return task;
}

bool canEditTask(const Json::Value& task, const Json::Value& claims) {
    if (isAdmin(claims)) return true;
    return task.get("created_by", "").asString() == claims.get("sub", "").asString();
}

Json::Value mergeAssignees(const Json::Value& task, const Json::Value& add, const Json::Value& remove) {
    std::vector<std::string> assignees;
    if (task["assignees"].isArray()) {
        for (const auto& val : task["assignees"]) {
            assignees.push_back(val.asString());
        }
    }
    if (add.isArray()) {
        for (const auto& val : add) {
            if (!val.isString()) continue;
            auto id = val.asString();
            if (std::find(assignees.begin(), assignees.end(), id) == assignees.end()) {
                assignees.push_back(id);
            }
        }
    }
    if (remove.isArray()) {
        for (const auto& val : remove) {
            if (!val.isString()) continue;
            auto id = val.asString();
            assignees.erase(std::remove(assignees.begin(), assignees.end(), id), assignees.end());
        }
    }
    Json::Value arr(Json::arrayValue);
    for (const auto& id : assignees) arr.append(id);
    return arr;
}

} // namespace

void TaskController::listTasks(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "TaskController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto userId = claims.get("sub", "").asString();
    auto status = req->getParameter("status");
    auto assignee = req->getParameter("assignee");
    auto project = req->getParameter("project");
    try {
        SurrealClient db;
        std::stringstream ss;
        ss << "SELECT * FROM task WHERE ";
        if (isAdmin(claims)) {
            ss << "true";
        } else {
            ss << "created_by = '" << drogon::utils::escapeHtml(userId) << "' OR array::contains(assignees, '" << drogon::utils::escapeHtml(userId) << "')";
        }
        if (!status.empty()) ss << " AND status = '" << drogon::utils::escapeHtml(status) << "'";
        if (!assignee.empty()) ss << " AND array::contains(assignees, '" << drogon::utils::escapeHtml(assignee) << "')";
        if (!project.empty()) ss << " AND project = '" << drogon::utils::escapeHtml(project) << "'";
        ss << " ORDER BY created_at DESC LIMIT 100;";
        auto res = db.exec(ss.str());
        Json::Value out;
        out["tasks"] = Json::Value(Json::arrayValue);
        if (res.isArray() && res.size() > 0) {
            for (const auto& row : res[0]["result"]) {
                out["tasks"].append(row);
            }
        }
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "tasks", __LINE__, "list failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","query failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void TaskController::createTask(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "TaskController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto json = req->getJsonObject();
    if (!json || !json->isMember("title")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","title required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    try {
        SurrealClient db;
        Json::Value rec;
        rec["title"] = (*json)["title"].asString();
        if (json->isMember("description")) rec["description"] = (*json)["description"];
        if (json->isMember("project")) rec["project"] = (*json)["project"];
        if (json->isMember("status")) rec["status"] = (*json)["status"];
        if (json->isMember("due_at")) rec["due_at"] = (*json)["due_at"];
        if (json->isMember("assignees")) rec["assignees"] = (*json)["assignees"];
        else rec["assignees"] = Json::Value(Json::arrayValue);
        rec["created_by"] = claims.get("sub", "").asString();
        auto task = db.createRecord("task", rec);
        Json::Value out;
        out["task"] = task;
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "tasks", __LINE__, "create failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","create failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void TaskController::updateTask(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& id) {
    constexpr auto className = "TaskController";
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
        auto task = ensureTask(db, id);
        if (!canEditTask(task, claims)) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
            resp->setStatusCode(k403Forbidden);
            return callback(resp);
        }
        Json::Value update(Json::objectValue);
        if (json->isMember("title")) update["title"] = (*json)["title"];
        if (json->isMember("description")) update["description"] = (*json)["description"];
        if (json->isMember("status")) update["status"] = (*json)["status"];
        if (json->isMember("due_at")) update["due_at"] = (*json)["due_at"];
        if (json->isMember("assignees")) update["assignees"] = (*json)["assignees"];
        if (update.getMemberNames().empty()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","no fields"}});
            resp->setStatusCode(k400BadRequest);
            return callback(resp);
        }
        auto updated = db.mergeRecord("task", id, update);
        Json::Value out;
        out["task"] = updated;
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "tasks", __LINE__, "update failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","update failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void TaskController::deleteTask(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& id) {
    constexpr auto className = "TaskController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    try {
        SurrealClient db;
        auto task = ensureTask(db, id);
        if (!canEditTask(task, claims)) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
            resp->setStatusCode(k403Forbidden);
            return callback(resp);
        }
        Json::Value update;
        update["status"] = "archived";
        update["updated_at"] = isoNow();
        db.mergeRecord("task", id, update);
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k204NoContent);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "tasks", __LINE__, "delete failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","delete failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void TaskController::updateAssignees(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& id) {
    constexpr auto className = "TaskController";
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
        auto task = ensureTask(db, id);
        if (!canEditTask(task, claims)) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
            resp->setStatusCode(k403Forbidden);
            return callback(resp);
        }
        auto newAssignees = mergeAssignees(task, json->get("add", Json::Value()), json->get("remove", Json::Value()));
        Json::Value update;
        update["assignees"] = newAssignees;
        auto updated = db.mergeRecord("task", id, update);
        Json::Value out;
        out["task"] = updated;
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "tasks", __LINE__, "assignee update failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","update failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void TaskController::updateStatus(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& id) {
    constexpr auto className = "TaskController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto json = req->getJsonObject();
    if (!json || !json->isMember("status")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","status required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    try {
        SurrealClient db;
        auto task = ensureTask(db, id);
        if (!canEditTask(task, claims)) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
            resp->setStatusCode(k403Forbidden);
            return callback(resp);
        }
        Json::Value update;
        update["status"] = (*json)["status"];
        update["updated_at"] = isoNow();
        auto updated = db.mergeRecord("task", id, update);
        Json::Value out;
        out["task"] = updated;
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "tasks", __LINE__, "status update failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","update failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}
