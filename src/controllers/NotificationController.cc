#include "NotificationController.h"
#include <drogon/drogon.h>
#include "../db/SurrealClient.h"
#include "../utils/logging.hpp"
#include <sstream>
#include <chrono>
#include <iomanip>
#include <ctime>

using namespace drogon;

namespace {
std::string isoNow() {
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *gmtime(&tt);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

int safeLimit(const std::string& param, int def, int max) {
    int value = def;
    if (!param.empty()) {
        try { value = std::stoi(param); } catch (...) {}
    }
    if (value < 1) value = 1;
    if (value > max) value = max;
    return value;
}

} // namespace

void NotificationController::listNotifications(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "NotificationController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto userId = claims.get("sub", "").asString();
    auto status = req->getParameter("status");
    auto limit = safeLimit(req->getParameter("limit"), 50, 200);
    try {
        SurrealClient db;
        std::stringstream ss;
        ss << "SELECT * FROM notification WHERE user = '" << drogon::utils::escapeHtml(userId) << "'";
        if (status == "unread") {
            ss << " AND read_at = NONE";
        }
        ss << " ORDER BY created_at DESC LIMIT " << limit << ";";
        auto res = db.exec(ss.str());
        Json::Value out;
        out["notifications"] = Json::Value(Json::arrayValue);
        if (res.isArray() && res.size() > 0) {
            for (const auto& row : res[0]["result"]) {
                out["notifications"].append(row);
            }
        }
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "notifications", __LINE__, "list failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","query failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void NotificationController::markRead(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "NotificationController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto userId = claims.get("sub", "").asString();
    auto json = req->getJsonObject();
    if (!json || !json->isMember("ids") || !(*json)["ids"].isArray()) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","ids array required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    try {
        SurrealClient db;
        for (const auto& idVal : (*json)["ids"]) {
            if (!idVal.isString()) continue;
            std::stringstream ss;
            ss << "UPDATE notification SET read_at = '" << isoNow() << "' WHERE id = '" << drogon::utils::escapeHtml(idVal.asString()) << "' AND user = '" << drogon::utils::escapeHtml(userId) << "';";
            db.exec(ss.str());
        }
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k204NoContent);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "notifications", __LINE__, "mark read failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","mark failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void NotificationController::markAllRead(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "NotificationController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto userId = claims.get("sub", "").asString();
    try {
        SurrealClient db;
        std::stringstream ss;
        ss << "UPDATE notification SET read_at = '" << isoNow() << "' WHERE user = '" << drogon::utils::escapeHtml(userId) << "' AND read_at = NONE;";
        db.exec(ss.str());
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k204NoContent);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "notifications", __LINE__, "mark all failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","mark failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}
