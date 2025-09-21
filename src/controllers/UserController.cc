#include "UserController.h"
#include <drogon/drogon.h>
#include "../db/SurrealClient.h"
#include "../utils/logging.hpp"
#include "../utils/crypto.hpp"
#include <algorithm>
#include <cctype>
#include <memory>
#include <string>
#include <sstream>

using namespace drogon;

namespace {
bool isAdminClaims(const Json::Value& claims) {
    return claims.get("role","user").asString() == "admin";
}

Json::Value sanitizeUser(Json::Value user) {
    user.removeMember("password_hash");
    user.removeMember("pending_totp_secret");
    user.removeMember("totp_secret");
    user.removeMember("totp_backup_codes");
    return user;
}

void cacheUser(const std::string& key, const Json::Value& user) {
    auto redis = app().getRedisClient();
    redis->execCommandAsync(
        [](const drogon::nosql::RedisResult &){},
        [](const std::exception &){},
        "SETEX cache:user:%s %d %s",
        key.c_str(), 300, drogon::utils::toString(user).c_str());
}

Json::Value ensureUserById(SurrealClient& db, const std::string& id) {
    auto user = db.selectById("user", id);
    if (user.isNull()) {
        throw std::runtime_error("user not found");
    }
    return user;
}

void writeAudit(SurrealClient& db, const std::string& event, const std::string& actor, const Json::Value& metadata = Json::Value()) {
    try {
        Json::Value rec;
        if (!actor.empty()) rec["actor"] = actor;
        rec["event"] = event;
        if (!metadata.isNull()) rec["metadata"] = metadata;
        db.createRecord("audit_log", rec);
    } catch (const std::exception& e) {
        logging::error(__FILE__, "UserController", __func__, "audit", __LINE__, "audit write failed", "NONE", e.what(), "none");
    }
}

void invalidateCache(const std::string& userId) {
    auto redis = app().getRedisClient();
    redis->execCommandAsync(
        [](const drogon::nosql::RedisResult &){},
        [](const std::exception &){},
        "DEL cache:user:%s",
        userId.c_str());
}

std::string toLowerTrim(std::string s) {
    auto isspace2 = [](unsigned char c){return std::isspace(c);};
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [&](unsigned char c){return !isspace2(c);}));
    s.erase(std::find_if(s.rbegin(), s.rend(), [&](unsigned char c){return !isspace2(c);}).base(), s.end());
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){return std::tolower(c);});
    return s;
}

} // namespace

void UserController::me(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "UserController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto uid = claims.get("sub","").asString();
    auto redis = app().getRedisClient();
    redis->execCommandAsync(
        [callback, uid, claims](const drogon::nosql::RedisResult &r){
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
                auto email = claims.get("email","").asString();
                auto user = db.selectOneByEmail(email);
                auto sanitized = sanitizeUser(user);
                Json::Value out;
                out["user"] = sanitized;
                auto resp = HttpResponse::newHttpJsonResponse(out);
                callback(resp);
                cacheUser(uid, sanitized);
            } catch (const std::exception& e) {
                logging::error(__FILE__, className, __func__, "profile", __LINE__, "lookup failed", req->getMethodString(), e.what(), "post");
                auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","lookup failed"}});
                resp->setStatusCode(k500InternalServerError);
                callback(resp);
            }
        },
        [callback](const std::exception &e){
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","redis error"}});
            resp->setStatusCode(k500InternalServerError);
            callback(resp);
        },
        "GET cache:user:%s", uid.c_str());
}

void UserController::updateMe(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "UserController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto uid = claims.get("sub","").asString();
    auto json = req->getJsonObject();
    if (!json) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","body required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    Json::Value update(Json::objectValue);
    if (json->isMember("name")) update["name"] = (*json)["name"];
    if (json->isMember("avatar_url")) update["avatar_url"] = (*json)["avatar_url"];
    if (json->isMember("preferences")) update["preferences"] = (*json)["preferences"];
    if (update.getMemberNames().empty()) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","no fields"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    try {
        SurrealClient db;
        auto user = db.mergeRecord("user", uid, update);
        auto sanitized = sanitizeUser(user);
        cacheUser(uid, sanitized);
        Json::Value out;
        out["user"] = sanitized;
        writeAudit(db, "user.profile_updated", uid);
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "profile", __LINE__, "update failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","update failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void UserController::changePassword(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "UserController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto uid = claims.get("sub","").asString();
    auto json = req->getJsonObject();
    if (!json || !json->isMember("old_password") || !json->isMember("new_password")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","old_password and new_password required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    auto oldPass = (*json)["old_password"].asString();
    auto newPass = (*json)["new_password"].asString();
    if (newPass.size() < 8) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","password too short"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    try {
        SurrealClient db;
        auto user = ensureUserById(db, uid);
        if (!crypto::verify_password_pbkdf2(oldPass, user.get("password_hash", "").asString())) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","invalid password"}});
            resp->setStatusCode(k401Unauthorized);
            return callback(resp);
        }
        Json::Value update;
        update["password_hash"] = crypto::hash_password_pbkdf2(newPass);
        db.mergeRecord("user", uid, update);
        std::stringstream revoke;
        revoke << "UPDATE refresh_token SET revoked_at = time::now() WHERE user = '" << drogon::utils::escapeHtml(uid) << "';";
        db.exec(revoke.str());
        writeAudit(db, "user.password_changed", uid);
        invalidateCache(uid);
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k204NoContent);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "profile", __LINE__, "password change failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","change failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void UserController::listUsers(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "UserController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    if (!isAdminClaims(claims)) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
        resp->setStatusCode(k403Forbidden);
        return callback(resp);
    }
    int limit = 50;
    auto limitParam = req->getParameter("limit");
    if (!limitParam.empty()) {
        try { limit = std::stoi(limitParam); } catch (...) {}
    }
    limit = std::clamp(limit, 1, 200);
    int offset = 0;
    auto offsetParam = req->getParameter("offset");
    if (!offsetParam.empty()) {
        try { offset = std::stoi(offsetParam); } catch (...) {}
    }
    offset = std::max(0, offset);
    auto role = req->getParameter("role");
    auto status = req->getParameter("status");
    auto query = req->getParameter("q");
    try {
        SurrealClient db;
        std::stringstream ss;
        ss << "SELECT id, email, name, role, status, created_at, updated_at FROM user WHERE true";
        if (!role.empty()) ss << " AND role = '" << drogon::utils::escapeHtml(role) << "'";
        if (!status.empty()) ss << " AND status = '" << drogon::utils::escapeHtml(status) << "'";
        if (!query.empty()) {
            auto q = drogon::utils::escapeHtml("%" + query + "%");
            ss << " AND (string::lower(email) LIKE string::lower('" << q << "') OR string::lower(name) LIKE string::lower('" << q << "'))";
        }
        ss << " ORDER BY created_at DESC LIMIT " << limit << " OFFSET " << offset << ";";
        auto res = db.exec(ss.str());
        Json::Value out(Json::objectValue);
        out["results"] = Json::Value(Json::arrayValue);
        if (res.isArray() && res.size() > 0) {
            for (const auto& row : res[0]["result"]) {
                out["results"].append(sanitizeUser(row));
            }
        }
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "admin", __LINE__, "list failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","query failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void UserController::getUserById(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& id) {
    constexpr auto className = "UserController";
    auto attrs = req->getAttributes();
    if (!isAdminClaims(attrs->get<Json::Value>("claims"))) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
        resp->setStatusCode(k403Forbidden);
        return callback(resp);
    }
    try {
        SurrealClient db;
        auto user = ensureUserById(db, id);
        Json::Value out;
        out["user"] = sanitizeUser(user);
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","not found"}});
        resp->setStatusCode(k404NotFound);
        callback(resp);
    }
}

void UserController::updateUserById(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& id) {
    constexpr auto className = "UserController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    if (!isAdminClaims(claims)) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
        resp->setStatusCode(k403Forbidden);
        return callback(resp);
    }
    auto json = req->getJsonObject();
    if (!json) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","body required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    Json::Value update(Json::objectValue);
    if (json->isMember("role")) update["role"] = (*json)["role"];
    if (json->isMember("status")) update["status"] = (*json)["status"];
    if (json->isMember("email")) {
        auto email = (*json)["email"].asString();
        update["email"] = email;
        update["email_norm"] = toLowerTrim(email);
    }
    if (update.getMemberNames().empty()) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","no fields"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    try {
        SurrealClient db;
        auto user = db.mergeRecord("user", id, update);
        Json::Value out;
        out["user"] = sanitizeUser(user);
        writeAudit(db, "admin.user_updated", claims.get("sub", "").asString(), Json::Value{{"user_id", id}});
        invalidateCache(id);
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "admin", __LINE__, "update failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","update failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void UserController::deleteUserById(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& id) {
    constexpr auto className = "UserController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    if (!isAdminClaims(claims)) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
        resp->setStatusCode(k403Forbidden);
        return callback(resp);
    }
    try {
        SurrealClient db;
        db.softDelete("user", id);
        writeAudit(db, "admin.user_disabled", claims.get("sub", "").asString(), Json::Value{{"user_id", id}});
        invalidateCache(id);
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k204NoContent);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "admin", __LINE__, "delete failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","delete failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void UserController::bulkInvite(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "UserController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    if (!isAdminClaims(claims)) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
        resp->setStatusCode(k403Forbidden);
        return callback(resp);
    }
    auto json = req->getJsonObject();
    if (!json || !json->isMember("emails") || !(*json)["emails"].isArray()) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","emails array required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    try {
        SurrealClient db;
        Json::Value created(Json::arrayValue);
        for (const auto& val : (*json)["emails"]) {
            if (!val.isString()) continue;
            auto email = val.asString();
            auto code = crypto::random_token(6);
            Json::Value rec;
            rec["email"] = email;
            rec["invite_code"] = code;
            rec["invited_by"] = claims.get("sub", "").asString();
            auto invite = db.createRecord("user_invite", rec);
            created.append(invite);
        }
        writeAudit(db, "admin.bulk_invite", claims.get("sub", "").asString(), Json::Value{{"count", (Json::Int64)created.size()}});
        Json::Value out;
        out["invites"] = created;
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "admin", __LINE__, "bulk invite failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","bulk invite failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}
