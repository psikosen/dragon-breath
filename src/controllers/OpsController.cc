#include "OpsController.h"
#include <drogon/drogon.h>
#include "../db/SurrealClient.h"
#include "../utils/logging.hpp"
#include <sstream>

using namespace drogon;

namespace {
constexpr const char kClassName[] = "OpsController";

bool isAdmin(const Json::Value& claims) {
    return claims.get("role","user").asString() == "admin";
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

void OpsController::auditLogs(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    if (!isAdmin(claims)) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
        resp->setStatusCode(k403Forbidden);
        return callback(resp);
    }
    auto limit = safeLimit(req->getParameter("limit"), 100, 500);
    int offset = 0;
    auto offsetParam = req->getParameter("offset");
    if (!offsetParam.empty()) {
        try { offset = std::stoi(offsetParam); } catch (...) {}
    }
    if (offset < 0) offset = 0;
    auto eventParam = req->getParameter("event");
    try {
        SurrealClient db;
        std::stringstream ss;
        ss << "SELECT * FROM audit_log";
        if (!eventParam.empty()) {
            ss << " WHERE event = '" << drogon::utils::escapeHtml(eventParam) << "'";
        }
        ss << " ORDER BY created_at DESC LIMIT " << limit << " OFFSET " << offset << ";";
        auto res = db.exec(ss.str());
        Json::Value out;
        out["logs"] = Json::Value(Json::arrayValue);
        if (res.isArray() && res.size() > 0) {
            for (const auto& row : res[0]["result"]) {
                out["logs"].append(row);
            }
        }
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, kClassName, __func__, "ops", __LINE__, "audit logs failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","query failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void OpsController::metrics(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    if (!isAdmin(claims)) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
        resp->setStatusCode(k403Forbidden);
        return callback(resp);
    }
    try {
        SurrealClient db;
        auto users = db.exec("SELECT count() AS total FROM user;");
        auto projects = db.exec("SELECT count() AS total FROM project;");
        auto tasks = db.exec("SELECT count() AS total FROM task;");
        auto sessions = db.exec("SELECT count() AS total FROM session WHERE revoked_at = NONE;");
        std::ostringstream oss;
        oss << "# HELP app_up Application status\n# TYPE app_up gauge\napp_up 1\n";
        auto getCount = [](const Json::Value& res) -> int64_t {
            if (res.isArray() && res.size() > 0 && res[0]["result"].isArray() && res[0]["result"].size() > 0) {
                return res[0]["result"][0]["total"].asInt64();
            }
            return 0;
        };
        oss << "# HELP app_users_total Total users\n# TYPE app_users_total gauge\n";
        oss << "app_users_total " << getCount(users) << "\n";
        oss << "# HELP app_projects_total Total projects\n# TYPE app_projects_total gauge\n";
        oss << "app_projects_total " << getCount(projects) << "\n";
        oss << "# HELP app_tasks_total Total tasks\n# TYPE app_tasks_total gauge\n";
        oss << "app_tasks_total " << getCount(tasks) << "\n";
        oss << "# HELP app_sessions_active Active sessions\n# TYPE app_sessions_active gauge\n";
        oss << "app_sessions_active " << getCount(sessions) << "\n";
        auto resp = HttpResponse::newHttpResponse();
        resp->setContentTypeCode(CT_TEXT_PLAIN);
        resp->setBody(oss.str());
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, kClassName, __func__, "ops", __LINE__, "metrics failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","metrics failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void OpsController::flushCache(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    if (!isAdmin(claims)) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
        resp->setStatusCode(k403Forbidden);
        return callback(resp);
    }
    auto redis = app().getRedisClient();
    if (!redis) {
        logging::error(__FILE__, kClassName, __func__, "ops", __LINE__, "redis unavailable", req->getMethodString(), "", "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","redis unavailable"}});
        resp->setStatusCode(k500InternalServerError);
        return callback(resp);
    }
    static const char script[] =
        "local cursor='0'; local total=0; repeat local res=redis.call('SCAN', cursor, 'MATCH', ARGV[1], 'COUNT', 1000); cursor=res[1]; "
        "local keys=res[2]; local count=#keys; if count>0 then redis.call('DEL', unpack(keys)); total=total+count; end until cursor=='0'; return total;";
    auto httpReq = req;
    redis->execCommandAsync(
        [callback, httpReq](const drogon::nosql::RedisResult &result) {
            Json::Value body;
            body["deleted"] = static_cast<Json::Int64>(result.asInteger());
            auto resp = HttpResponse::newHttpJsonResponse(body);
            logging::info(__FILE__, kClassName, __func__, "ops", __LINE__, "cache flush completed", httpReq->getMethodString(), "", "post");
            callback(resp);
        },
        [callback, httpReq](const std::exception &e){
            logging::error(__FILE__, kClassName, __func__, "ops", __LINE__, "cache flush failed", httpReq->getMethodString(), e.what(), "post");
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","redis error"}});
            resp->setStatusCode(k500InternalServerError);
            callback(resp);
        },
        "EVAL %s 0 %s",
        script,
        "cache:*");
}
