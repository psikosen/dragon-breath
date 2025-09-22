#include "UserController.h"
#include <drogon/drogon.h>
#include "../db/SurrealClient.h"
#include "../utils/crypto.hpp"
#include "../utils/logging.hpp"
#include <chrono>
#include <sstream>
#include <optional>
#include <iomanip>
#include <algorithm>
#include <memory>

using namespace drogon;

namespace {
bool isAdminClaims(const Json::Value& claims) {
    return claims.get("role", "user").asString() == "admin";
}

Json::Value sanitize(const Json::Value& user) {
    Json::Value copy = user;
    copy.removeMember("password_hash");
    copy.removeMember("totp_secret");
    copy.removeMember("backup_codes");
    return copy;
}

std::string recordIdPart(const std::string& rid) {
    auto pos = rid.find(':');
    if (pos == std::string::npos) {
        return rid;
    }
    return rid.substr(pos + 1);
}

std::string isoNow() {
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &tt);
#else
    gmtime_r(&tt, &tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

void audit(SurrealClient& db,
           const Json::Value& claims,
           const std::string& action,
           const std::string& resourceType,
           const std::string& resourceId,
           const Json::Value& meta = Json::Value(Json::objectValue)) {
    auto actor = claims.get("sub", "").asString();
    db.recordAudit(actor.empty() ? "system" : actor, action, resourceType, resourceId, meta);
}

void invalidateCache(const std::string& userId) {
    auto redis = app().getRedisClient();
    redis->execCommandAsync(
        [](const drogon::nosql::RedisResult &) {},
        [](const std::exception &) {},
        "DEL cache:user:%s", userId.c_str());
}

std::string methodName(const HttpRequestPtr& req) {
    switch (req->getMethod()) {
        case Get: return "GET";
        case Post: return "POST";
        case Patch: return "PATCH";
        case Delete: return "DELETE";
        case Put: return "PUT";
        default: return "NONE";
    }
}

} // namespace

void UserController::me(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto redis = app().getRedisClient();
    auto uid = claims.get("sub", "").asString();
    redis->execCommandAsync(
        [callback, uid](const drogon::nosql::RedisResult &r){
            if (r.type() != drogon::nosql::RedisResultType::kNil) {
                Json::Value user;
                Json::CharReaderBuilder rb;
                std::string errs;
                auto s = r.asString();
                std::unique_ptr<Json::CharReader> reader(rb.newCharReader());
                if (reader->parse(s.data(), s.data()+s.size(), &user, &errs)) {
                    Json::Value out;
                    out["user"] = user;
                    auto resp = HttpResponse::newHttpJsonResponse(out);
                    callback(resp);
                    return;
                }
            }
            try {
                SurrealClient db;
                auto email = claims.get("email", "").asString();
                auto user = db.selectOneByEmail(email);
                Json::Value out;
                out["user"] = sanitize(user);
                auto resp = HttpResponse::newHttpJsonResponse(out);
                callback(resp);
                app().getRedisClient()->execCommandAsync(
                    [](const drogon::nosql::RedisResult &){},
                    [](const std::exception &){},
                    "SETEX cache:user:%s %d %s",
                    uid.c_str(), 300, drogon::utils::toString(sanitize(user)).c_str());
            } catch (...) {
                auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "lookup failed"}});
                resp->setStatusCode(k500InternalServerError);
                callback(resp);
            }
        },
        [callback](const std::exception &){
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "redis error"}});
            resp->setStatusCode(k500InternalServerError);
            callback(resp);
        },
        "GET cache:user:%s", uid.c_str());
}

void UserController::updateMe(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    auto json = req->getJsonObject();
    if (!json) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "invalid json"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    Json::Value update(Json::objectValue);
    if ((*json).isMember("name")) update["name"] = (*json)["name"];
    if ((*json).isMember("avatar")) update["avatar"] = (*json)["avatar"];
    if ((*json).isMember("preferences")) update["preferences"] = (*json)["preferences"];
    if (update.empty()) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"status", "no changes"}});
        return callback(resp);
    }
    update["profile_updated_at"] = isoNow();
    try {
        SurrealClient db;
        db.updateRecord("user", recordIdPart(claims.get("sub", "").asString()), update);
        invalidateCache(claims.get("sub", "").asString());
        audit(db, claims, "profile_update", "user", claims.get("sub", "").asString(), update);
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"status", "ok"}});
        callback(resp);
    } catch (const std::exception& e) {
        logging::error("UserController.cc", "UserController", "updateMe", "user", __LINE__, e.what(), methodName(req), e.what());
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "update failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void UserController::changePassword(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    auto json = req->getJsonObject();
    if (!json || !(*json).isMember("current") || !(*json).isMember("next")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "current and next required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    auto current = (*json)["current"].asString();
    auto next = (*json)["next"].asString();
    if (next.size() < 8) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "password too short"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    try {
        SurrealClient db;
        auto user = db.selectById("user", recordIdPart(claims.get("sub", "").asString()));
        if (user.isNull() || !crypto::verify_password_pbkdf2(current, user.get("password_hash", "").asString())) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "invalid password"}});
            resp->setStatusCode(k401Unauthorized);
            return callback(resp);
        }
        Json::Value update;
        update["password_hash"] = crypto::hash_password_pbkdf2(next);
        update["profile_updated_at"] = isoNow();
        db.updateRecord("user", recordIdPart(user["id"].asString()), update);
        invalidateCache(claims.get("sub", "").asString());
        audit(db, claims, "password_change", "user", user["id"].asString(), Json::Value());
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"status", "ok"}});
        callback(resp);
    } catch (const std::exception& e) {
        logging::error("UserController.cc", "UserController", "changePassword", "user", __LINE__, e.what(), methodName(req), e.what());
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "change failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void UserController::listUsers(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    if (!isAdminClaims(claims)) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "forbidden"}});
        resp->setStatusCode(k403Forbidden);
        return callback(resp);
    }
    try {
        SurrealClient db;
        auto res = db.exec("SELECT id, email, name, role, status, created_at, updated_at FROM user WHERE deleted_at = NONE OR deleted_at = NULL ORDER BY created_at DESC LIMIT 200;");
        Json::Value out;
        out["result_sets"] = res;
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error("UserController.cc", "UserController", "listUsers", "user", __LINE__, e.what(), methodName(req), e.what());
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "query failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void UserController::getUser(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, std::string userId) {
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    if (!isAdminClaims(claims)) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "forbidden"}});
        resp->setStatusCode(k403Forbidden);
        return callback(resp);
    }
    try {
        SurrealClient db;
        auto user = db.selectById("user", userId);
        if (user.isNull()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "not found"}});
            resp->setStatusCode(k404NotFound);
            return callback(resp);
        }
        Json::Value out;
        out["user"] = sanitize(user);
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error("UserController.cc", "UserController", "getUser", "user", __LINE__, e.what(), methodName(req), e.what());
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void UserController::updateUser(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, std::string userId) {
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    if (!isAdminClaims(claims)) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "forbidden"}});
        resp->setStatusCode(k403Forbidden);
        return callback(resp);
    }
    auto json = req->getJsonObject();
    if (!json) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "invalid json"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    Json::Value update(Json::objectValue);
    if ((*json).isMember("role")) update["role"] = (*json)["role"];
    if ((*json).isMember("status")) update["status"] = (*json)["status"];
    if (update.empty()) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"status", "no changes"}});
        return callback(resp);
    }
    if (update.isMember("status") && update["status"].asString() == "disabled") {
        update["deleted_at"] = isoNow();
    }
    try {
        SurrealClient db;
        db.updateRecord("user", userId, update);
        invalidateCache("user:" + userId);
        audit(db, claims, "admin_user_update", "user", "user:" + userId, update);
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"status", "ok"}});
        callback(resp);
    } catch (const std::exception& e) {
        logging::error("UserController.cc", "UserController", "updateUser", "user", __LINE__, e.what(), methodName(req), e.what());
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "update failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void UserController::deleteUser(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, std::string userId) {
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    if (!isAdminClaims(claims)) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "forbidden"}});
        resp->setStatusCode(k403Forbidden);
        return callback(resp);
    }
    try {
        SurrealClient db;
        Json::Value update;
        update["status"] = "disabled";
        update["deleted_at"] = isoNow();
        db.updateRecord("user", userId, update);
        invalidateCache("user:" + userId);
        audit(db, claims, "admin_user_delete", "user", "user:" + userId, Json::Value());
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k204NoContent);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error("UserController.cc", "UserController", "deleteUser", "user", __LINE__, e.what(), methodName(req), e.what());
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "delete failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void UserController::bulkInvite(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    if (!isAdminClaims(claims)) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "forbidden"}});
        resp->setStatusCode(k403Forbidden);
        return callback(resp);
    }
    auto json = req->getJsonObject();
    if (!json || !(*json).isMember("emails") || !(*json)["emails"].isArray()) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "emails array required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    try {
        SurrealClient db;
        Json::Value created(Json::arrayValue);
        for (const auto& emailVal : (*json)["emails"]) {
            auto email = emailVal.asString();
            if (email.empty()) continue;
            auto normalized = email;
            std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char c){ return std::tolower(c); });
            auto token = crypto::random_token_hex(16);
            Json::Value invite;
            invite["email"] = normalized;
            invite["invited_by"] = claims.get("sub", "").asString();
            invite["token_hash"] = crypto::sha256_hex(token);
            invite["status"] = "pending";
            db.createRecord("invite", drogon::utils::getUuid(), invite);
            Json::Value item;
            item["email"] = normalized;
            item["token"] = token;
            created.append(item);
        }
        audit(db, claims, "bulk_invite", "invite", "batch", Json::Value{{"count", static_cast<Json::Int64>(created.size())}});
        Json::Value out;
        out["invites"] = created;
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error("UserController.cc", "UserController", "bulkInvite", "user", __LINE__, e.what(), methodName(req), e.what());
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "invite failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}
