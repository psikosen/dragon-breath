#include "SessionController.h"
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

} // namespace

void SessionController::listSessions(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "SessionController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto userId = claims.get("sub", "").asString();
    try {
        SurrealClient db;
        std::stringstream ss;
        ss << "SELECT * FROM session WHERE user = '" << drogon::utils::escapeHtml(userId) << "' ORDER BY created_at DESC LIMIT 50;";
        auto res = db.exec(ss.str());
        Json::Value out;
        out["sessions"] = Json::Value(Json::arrayValue);
        if (res.isArray() && res.size() > 0) {
            for (const auto& row : res[0]["result"]) {
                out["sessions"].append(row);
            }
        }
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "sessions", __LINE__, "list failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","query failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void SessionController::revokeSession(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& id) {
    constexpr auto className = "SessionController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto userId = claims.get("sub", "").asString();
    try {
        SurrealClient db;
        auto session = db.selectById("session", id);
        if (session.isNull() || session.get("user", "").asString() != userId) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","not found"}});
            resp->setStatusCode(k404NotFound);
            return callback(resp);
        }
        Json::Value update;
        update["revoked_at"] = isoNow();
        db.mergeRecord("session", id, update);
        std::stringstream ss;
        ss << "UPDATE refresh_token SET revoked_at = time::now() WHERE session_id = '" << drogon::utils::escapeHtml(id) << "';";
        db.exec(ss.str());
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k204NoContent);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "sessions", __LINE__, "revoke failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","revoke failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}
