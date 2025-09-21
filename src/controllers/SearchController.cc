#include "SearchController.h"
#include <drogon/drogon.h>
#include "../db/SurrealClient.h"
#include "../utils/logging.hpp"
#include <sstream>

using namespace drogon;

namespace {
bool isAdmin(const Json::Value& claims) {
    return claims.get("role","user").asString() == "admin";
}

Json::Value firstSet(const Json::Value& res) {
    if (res.isArray() && res.size() > 0) {
        return res[0]["result"];
    }
    return Json::Value(Json::arrayValue);
}

} // namespace

void SearchController::search(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "SearchController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto query = req->getParameter("q");
    if (query.empty()) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","q required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    auto scope = req->getParameter("scope");
    try {
        SurrealClient db;
        Json::Value out(Json::objectValue);
        auto escaped = drogon::utils::escapeHtml("%" + query + "%");
        std::stringstream projectQuery;
        projectQuery << "SELECT id, name, status FROM project WHERE string::lower(name) LIKE string::lower('" << escaped << "')";
        if (!isAdmin(claims)) {
            projectQuery << " AND created_by = '" << drogon::utils::escapeHtml(claims.get("sub", "").asString()) << "'";
        }
        projectQuery << " LIMIT 10;";
        if (scope.empty() || scope == "projects") {
            out["projects"] = firstSet(db.exec(projectQuery.str()));
        }
        if (scope.empty() || scope == "tasks") {
            std::stringstream taskQuery;
            taskQuery << "SELECT id, title, status FROM task WHERE string::lower(title) LIKE string::lower('" << escaped << "')";
            if (!isAdmin(claims)) {
                taskQuery << " AND created_by = '" << drogon::utils::escapeHtml(claims.get("sub", "").asString()) << "'";
            }
            taskQuery << " LIMIT 10;";
            out["tasks"] = firstSet(db.exec(taskQuery.str()));
        }
        if (scope.empty() || scope == "users") {
            if (isAdmin(claims)) {
                std::stringstream userQuery;
                userQuery << "SELECT id, email, name FROM user WHERE string::lower(email) LIKE string::lower('" << escaped << "') OR string::lower(name) LIKE string::lower('" << escaped << "') LIMIT 10;";
                out["users"] = firstSet(db.exec(userQuery.str()));
            } else {
                out["users"] = Json::Value(Json::arrayValue);
            }
        }
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "search", __LINE__, "search failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","search failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}
