#include "ApiKeyController.h"
#include <drogon/drogon.h>
#include "../db/SurrealClient.h"
#include "../utils/logging.hpp"
#include "../utils/crypto.hpp"
#include <sstream>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <stdexcept>

using namespace drogon;

namespace {
Json::Value sanitizeKey(Json::Value key) {
    key.removeMember("token_hash");
    return key;
}

std::string isoNow() {
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *gmtime(&tt);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

} // namespace

void ApiKeyController::listKeys(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "ApiKeyController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto userId = claims.get("sub", "").asString();
    try {
        SurrealClient db;
        std::stringstream ss;
        ss << "SELECT id, name, scopes, expires_at, created_at, last_used_at, rotated_at, revoked_at FROM api_key WHERE user = '" << drogon::utils::escapeHtml(userId) << "' ORDER BY created_at DESC;";
        auto res = db.exec(ss.str());
        Json::Value out;
        out["api_keys"] = Json::Value(Json::arrayValue);
        if (res.isArray() && res.size() > 0) {
            for (const auto& row : res[0]["result"]) {
                out["api_keys"].append(row);
            }
        }
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "api_keys", __LINE__, "list failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","query failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void ApiKeyController::createKey(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "ApiKeyController";
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
        rec["user"] = claims.get("sub", "").asString();
        if (json->isMember("scopes")) rec["scopes"] = (*json)["scopes"];
        if (json->isMember("expires_at")) rec["expires_at"] = (*json)["expires_at"];
        auto raw = "key_" + crypto::random_token(24);
        rec["token_hash"] = crypto::bcrypt_style_hash(raw);
        auto key = db.createRecord("api_key", rec);
        Json::Value out;
        out["api_key"] = sanitizeKey(key);
        out["secret"] = raw;
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "api_keys", __LINE__, "create failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","create failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void ApiKeyController::deleteKey(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& id) {
    constexpr auto className = "ApiKeyController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto userId = claims.get("sub", "").asString();
    try {
        SurrealClient db;
        auto key = db.selectById("api_key", id);
        if (key.isNull() || key.get("user", "").asString() != userId) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","not found"}});
            resp->setStatusCode(k404NotFound);
            return callback(resp);
        }
        Json::Value update;
        update["revoked_at"] = isoNow();
        db.mergeRecord("api_key", id, update);
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k204NoContent);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "api_keys", __LINE__, "delete failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","delete failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void ApiKeyController::rotateKey(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& id) {
    constexpr auto className = "ApiKeyController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto userId = claims.get("sub", "").asString();
    try {
        SurrealClient db;
        auto key = db.selectById("api_key", id);
        if (key.isNull() || key.get("user", "").asString() != userId) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","not found"}});
            resp->setStatusCode(k404NotFound);
            return callback(resp);
        }
        auto raw = "key_" + crypto::random_token(24);
        Json::Value update;
        update["token_hash"] = crypto::bcrypt_style_hash(raw);
        update["rotated_at"] = isoNow();
        db.mergeRecord("api_key", id, update);
        Json::Value out;
        out["secret"] = raw;
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "api_keys", __LINE__, "rotate failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","rotate failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}
