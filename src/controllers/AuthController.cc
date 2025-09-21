#include "AuthController.h"
#include <drogon/drogon.h>
#include "../db/SurrealClient.h"
#include "../utils/crypto.hpp"
#include "../utils/jwt.hpp"
#include "../utils/totp.hpp"
#include "../utils/logging.hpp"
#include <chrono>
#include <optional>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <vector>
#include <ctime>

using namespace drogon;

namespace {
std::string toLowerTrim(std::string s) {
    auto isspace2 = [](unsigned char c){return std::isspace(c);};
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [&](unsigned char c){return !isspace2(c);}));
    s.erase(std::find_if(s.rbegin(), s.rend(), [&](unsigned char c){return !isspace2(c);}).base(), s.end());
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){return std::tolower(c);});
    return s;
}

std::string getJwtSecret() {
    const char* sec = std::getenv("JWT_SECRET");
    return sec ? std::string(sec) : std::string("change_me_dev_secret");
}

std::string isoTimestamp(const std::chrono::system_clock::time_point& tp) {
    auto tt = std::chrono::system_clock::to_time_t(tp);
    std::tm tm = *gmtime(&tt);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

Json::Value sanitizeUser(Json::Value user) {
    user.removeMember("password_hash");
    user.removeMember("pending_totp_secret");
    user.removeMember("totp_secret");
    return user;
}

void writeAudit(SurrealClient& db, const std::string& event, const std::string& actor, const Json::Value& metadata = Json::Value()) {
    try {
        Json::Value rec;
        if (!actor.empty()) {
            rec["actor"] = actor;
        }
        rec["event"] = event;
        if (!metadata.isNull()) {
            rec["metadata"] = metadata;
        }
        db.createRecord("audit_log", rec);
    } catch (const std::exception& e) {
        logging::error(__FILE__, "AuthController", __func__, "audit", __LINE__, "audit write failed", "NONE", e.what(), "none");
    }
}

Json::Value createSessionRecord(SurrealClient& db, const Json::Value& user, const HttpRequestPtr& req, const std::string& jti) {
    Json::Value content;
    content["user"] = user["id"].asString();
    content["jti"] = jti;
    auto agent = req->getHeader("User-Agent");
    if (!agent.empty()) {
        content["user_agent"] = agent;
    }
    auto peer = req->getPeerAddr();
    content["ip"] = peer.toIp();
    return db.createRecord("session", content);
}

Json::Value createRefreshTokenRecord(SurrealClient& db, const std::string& userId, const std::string& sessionId, const std::string& tokenHash, const std::string& expiresAtIso) {
    Json::Value content;
    content["user"] = userId;
    content["session_id"] = sessionId;
    content["token_hash"] = tokenHash;
    content["expires_at"] = expiresAtIso;
    return db.createRecord("refresh_token", content);
}

Json::Value issueTokens(SurrealClient& db, const Json::Value& user, const HttpRequestPtr& req, Json::Value& sessionOut) {
    constexpr auto className = "AuthController";
    auto now = std::chrono::system_clock::now();
    auto accessExp = now + std::chrono::minutes(15);
    auto refreshExp = now + std::chrono::hours(24 * 30);
    auto issuedAt = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    auto accessExpSeconds = std::chrono::duration_cast<std::chrono::seconds>(accessExp.time_since_epoch()).count();

    auto jti = drogon::utils::getUuid();
    sessionOut = createSessionRecord(db, user, req, jti);

    Json::Value claims;
    claims["sub"] = user["id"].asString();
    claims["email"] = user.get("email_norm", user.get("email", "")).asString();
    claims["role"] = user.get("role","user").asString();
    claims["iat"] = static_cast<Json::Int64>(issuedAt);
    claims["exp"] = static_cast<Json::Int64>(accessExpSeconds);
    claims["jti"] = jti;
    claims["session_id"] = sessionOut["id"].asString();
    if (user.get("totp_enabled", false).asBool()) {
        claims["mfa"] = "totp";
    }

    auto accessToken = jwt::create_hs256(claims, getJwtSecret());
    auto refreshRaw = crypto::random_token(32);
    auto refreshHash = crypto::sha256_hex(refreshRaw);
    auto refreshRecord = createRefreshTokenRecord(db, user["id"].asString(), sessionOut["id"].asString(), refreshHash, isoTimestamp(refreshExp));

    Json::Value out;
    out["access_token"] = accessToken;
    out["refresh_token"] = refreshRaw;
    out["expires_in"] = static_cast<Json::Int64>(std::chrono::duration_cast<std::chrono::seconds>(accessExp - now).count());
    out["refresh_expires_at"] = refreshRecord["expires_at"].asString();
    out["session"] = sessionOut;

    Json::Value auditMeta;
    auditMeta["session_id"] = sessionOut["id"].asString();
    writeAudit(db, "auth.token_issued", user["id"].asString(), auditMeta);
    logging::info(__FILE__, className, __func__, "auth", __LINE__, "issued new token pair", "POST");
    return out;
}

void revokeSession(SurrealClient& db, const std::string& sessionId) {
    if (sessionId.empty()) return;
    Json::Value update;
    update["revoked_at"] = isoTimestamp(std::chrono::system_clock::now());
    try {
        db.mergeRecord("session", sessionId, update);
        std::stringstream ss;
        ss << "UPDATE refresh_token SET revoked_at = time::now() WHERE session_id = '" << drogon::utils::escapeHtml(sessionId) << "';";
        db.exec(ss.str());
    } catch (const std::exception& e) {
        logging::error(__FILE__, "AuthController", __func__, "auth", __LINE__, "session revoke failed", "NONE", e.what(), "post");
    }
}

bool consumeBackupCode(SurrealClient& db, Json::Value& user, const std::string& code) {
    if (code.empty()) return false;
    auto hashed = crypto::sha256_hex(code);
    auto arr = user["totp_backup_codes"];
    if (!arr.isArray()) return false;
    Json::Value newArr(Json::arrayValue);
    bool matched = false;
    for (const auto& entry : arr) {
        if (!matched && entry.asString() == hashed) {
            matched = true;
            continue;
        }
        newArr.append(entry);
    }
    if (matched) {
        Json::Value update;
        update["totp_backup_codes"] = newArr;
        db.mergeRecord("user", user["id"].asString(), update);
        user["totp_backup_codes"] = newArr;
    }
    return matched;
}

void updateUserLastLogin(SurrealClient& db, const Json::Value& user) {
    Json::Value update;
    update["last_login_at"] = isoTimestamp(std::chrono::system_clock::now());
    db.mergeRecord("user", user["id"].asString(), update);
}

void queueEmailVerification(SurrealClient& db, const Json::Value& user) {
    if (user.get("email_verified", false).asBool()) return;
    auto code = crypto::random_token(8);
    Json::Value rec;
    rec["user"] = user["id"].asString();
    rec["code"] = code;
    rec["expires_at"] = isoTimestamp(std::chrono::system_clock::now() + std::chrono::hours(24));
    db.createRecord("email_verification", rec);
}

std::vector<std::string> hashCodes(const std::vector<std::string>& codes) {
    std::vector<std::string> hashed;
    hashed.reserve(codes.size());
    for (const auto& c : codes) {
        hashed.push_back(crypto::sha256_hex(c));
    }
    return hashed;
}

} // namespace

void AuthController::registerUser(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "AuthController";
    auto json = req->getJsonObject();
    if (!json || !json->isMember("email") || !json->isMember("password")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","email and password required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    auto email = (*json)["email"].asString();
    auto pass  = (*json)["password"].asString();
    if (pass.size() < 8) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","password too short"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    try {
        SurrealClient db;
        auto emailNorm = toLowerTrim(email);
        auto existing = db.selectOneByEmail(emailNorm);
        if (!existing.isNull()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","email already exists"}});
            resp->setStatusCode(k409Conflict);
            return callback(resp);
        }
        auto hash = crypto::hash_password_pbkdf2(pass);
        auto role = "user";
        auto firstUserQuery = db.exec("SELECT count() AS total FROM user LIMIT 1;");
        if (firstUserQuery.isArray() && firstUserQuery[0]["result"].isArray() && firstUserQuery[0]["result"][0]["total"].asInt() == 0) {
            role = "admin";
        }
        auto user = db.createUser(email, emailNorm, hash, role);
        queueEmailVerification(db, user);
        Json::Value session;
        auto tokens = issueTokens(db, user, req, session);
        updateUserLastLogin(db, user);
        auto respBody = Json::Value(Json::objectValue);
        respBody["access_token"] = tokens["access_token"]; // backward compatibility
        respBody["refresh_token"] = tokens["refresh_token"];
        respBody["expires_in"] = tokens["expires_in"];
        respBody["refresh_expires_at"] = tokens["refresh_expires_at"];
        respBody["session"] = tokens["session"];
        respBody["user"] = sanitizeUser(user);
        logging::info(__FILE__, className, __func__, "auth", __LINE__, "user registered", "POST", "", "post");
        auto resp = HttpResponse::newHttpJsonResponse(respBody);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "auth", __LINE__, "registration failed", "POST", e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","registration failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void AuthController::login(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "AuthController";
    auto json = req->getJsonObject();
    if (!json || !json->isMember("email") || !json->isMember("password")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","email and password required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    auto emailNorm = toLowerTrim((*json)["email"].asString());
    auto pass = (*json)["password"].asString();
    auto totpCode = json->get("totp_code", "").asString();
    auto backupCode = json->get("backup_code", "").asString();
    try {
        SurrealClient db;
        auto user = db.selectOneByEmail(emailNorm);
        if (user.isNull()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","invalid credentials"}});
            resp->setStatusCode(k401Unauthorized);
            return callback(resp);
        }
        auto stored = user.get("password_hash","").asString();
        if (!crypto::verify_password_pbkdf2(pass, stored)) {
            logging::info(__FILE__, className, __func__, "auth", __LINE__, "invalid password", "POST");
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","invalid credentials"}});
            resp->setStatusCode(k401Unauthorized);
            return callback(resp);
        }
        if (user.get("totp_enabled", false).asBool()) {
            if (totpCode.empty() && backupCode.empty()) {
                auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","mfa required"}});
                resp->setStatusCode(k401Unauthorized);
                return callback(resp);
            }
            auto secret = user.get("totp_secret", "").asString();
            bool ok = false;
            if (!secret.empty() && !totpCode.empty()) {
                ok = totp::verify(secret, totpCode);
            }
            if (!ok && !backupCode.empty()) {
                ok = consumeBackupCode(db, user, backupCode);
            }
            if (!ok) {
                auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","invalid mfa"}});
                resp->setStatusCode(k401Unauthorized);
                return callback(resp);
            }
        }
        Json::Value session;
        auto tokens = issueTokens(db, user, req, session);
        updateUserLastLogin(db, user);
        auto respBody = Json::Value(Json::objectValue);
        respBody["access_token"] = tokens["access_token"];
        respBody["refresh_token"] = tokens["refresh_token"];
        respBody["expires_in"] = tokens["expires_in"];
        respBody["refresh_expires_at"] = tokens["refresh_expires_at"];
        respBody["session"] = tokens["session"];
        respBody["user"] = sanitizeUser(user);
        auto resp = HttpResponse::newHttpJsonResponse(respBody);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "auth", __LINE__, "login failed", "POST", e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","login failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void AuthController::logout(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "AuthController";
    auto attrs = req->getAttributes();
    if (!attrs->find("claims")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","no claims"}});
        resp->setStatusCode(k401Unauthorized);
        return callback(resp);
    }
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto jti = claims.get("jti","").asString();
    auto exp = claims.get("exp", (Json::Int64)std::time(nullptr)).asInt64();
    auto now = (Json::Int64)std::time(nullptr);
    auto ttl = (int)std::max<Json::Int64>(0, exp - now);
    auto sessionId = claims.get("session_id", "").asString();
    try {
        SurrealClient db;
        revokeSession(db, sessionId);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "auth", __LINE__, "logout revoke failed", "POST", e.what(), "post");
    }

    auto redis = app().getRedisClient();
    redis->execCommandAsync(
        [callback](const drogon::nosql::RedisResult &){
            auto resp = HttpResponse::newHttpResponse();
            resp->setStatusCode(k204NoContent);
            callback(resp);
        },
        [callback](const std::exception &e){
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","redis error"}});
            resp->setStatusCode(k500InternalServerError);
            callback(resp);
        },
        "SETEX blacklist:jti:%s %d 1", jti.c_str(), ttl);
    logging::info(__FILE__, className, __func__, "auth", __LINE__, "logout processed", "POST");
}

void AuthController::refresh(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "AuthController";
    auto json = req->getJsonObject();
    if (!json || !json->isMember("refresh_token")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","refresh_token required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    auto refreshToken = (*json)["refresh_token"].asString();
    try {
        SurrealClient db;
        auto hash = crypto::sha256_hex(refreshToken);
        std::stringstream ss;
        ss << "SELECT * FROM refresh_token WHERE token_hash = '" << drogon::utils::escapeHtml(hash) << "' LIMIT 1;";
        auto res = db.exec(ss.str());
        auto record = Json::Value(Json::nullValue);
        if (res.isArray() && res.size() > 0 && res[0]["result"].isArray() && res[0]["result"].size() > 0) {
            record = res[0]["result"][0];
        }
        if (record.isNull() || record.isMember("revoked_at") && !record["revoked_at"].isNull()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","invalid refresh token"}});
            resp->setStatusCode(k401Unauthorized);
            return callback(resp);
        }
        auto expiresAt = record.get("expires_at", "").asString();
        auto nowIso = isoTimestamp(std::chrono::system_clock::now());
        if (!expiresAt.empty() && nowIso > expiresAt) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","refresh expired"}});
            resp->setStatusCode(k401Unauthorized);
            return callback(resp);
        }
        auto userId = record.get("user", "").asString();
        if (userId.empty()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","invalid refresh token"}});
            resp->setStatusCode(k401Unauthorized);
            return callback(resp);
        }
        auto user = db.selectById("user", userId);
        if (user.isNull()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","user not found"}});
            resp->setStatusCode(k401Unauthorized);
            return callback(resp);
        }
        Json::Value update;
        update["rotated_at"] = isoTimestamp(std::chrono::system_clock::now());
        update["revoked_at"] = isoTimestamp(std::chrono::system_clock::now());
        db.mergeRecord("refresh_token", record["id"].asString(), update);

        Json::Value session;
        auto tokens = issueTokens(db, user, req, session);
        Json::Value out;
        out["access_token"] = tokens["access_token"];
        out["refresh_token"] = tokens["refresh_token"];
        out["expires_in"] = tokens["expires_in"];
        out["refresh_expires_at"] = tokens["refresh_expires_at"];
        out["session"] = tokens["session"];
        out["user"] = sanitizeUser(user);
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "auth", __LINE__, "refresh failed", "POST", e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","refresh failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void AuthController::forgotPassword(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "AuthController";
    auto json = req->getJsonObject();
    if (!json || !json->isMember("email")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","email required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    auto emailNorm = toLowerTrim((*json)["email"].asString());
    try {
        SurrealClient db;
        auto user = db.selectOneByEmail(emailNorm);
        if (!user.isNull()) {
            auto code = crypto::random_token(6);
            Json::Value rec;
            rec["user"] = user["id"].asString();
            rec["code"] = code;
            rec["expires_at"] = isoTimestamp(std::chrono::system_clock::now() + std::chrono::minutes(30));
            db.createRecord("password_reset", rec);
            writeAudit(db, "auth.password_reset_requested", user["id"].asString());
        }
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k204NoContent);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "auth", __LINE__, "forgot password failed", "POST", e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","request failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void AuthController::resetPassword(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "AuthController";
    auto json = req->getJsonObject();
    if (!json || !json->isMember("code") || !json->isMember("password")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","code and password required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    auto code = (*json)["code"].asString();
    auto newPass = (*json)["password"].asString();
    if (newPass.size() < 8) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","password too short"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    try {
        SurrealClient db;
        std::stringstream ss;
        ss << "SELECT * FROM password_reset WHERE code = '" << drogon::utils::escapeHtml(code) << "' LIMIT 1;";
        auto res = db.exec(ss.str());
        Json::Value record;
        if (res.isArray() && res.size() > 0 && res[0]["result"].isArray() && res[0]["result"].size() > 0) {
            record = res[0]["result"][0];
        }
        if (record.isNull() || (record.isMember("used_at") && !record["used_at"].isNull())) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","invalid code"}});
            resp->setStatusCode(k400BadRequest);
            return callback(resp);
        }
        auto expires = record.get("expires_at", "").asString();
        auto nowIso = isoTimestamp(std::chrono::system_clock::now());
        if (!expires.empty() && nowIso > expires) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","code expired"}});
            resp->setStatusCode(k400BadRequest);
            return callback(resp);
        }
        auto userId = record.get("user", "").asString();
        auto hash = crypto::hash_password_pbkdf2(newPass);
        Json::Value update;
        update["password_hash"] = hash;
        db.mergeRecord("user", userId, update);
        Json::Value mark;
        mark["used_at"] = isoTimestamp(std::chrono::system_clock::now());
        db.mergeRecord("password_reset", record["id"].asString(), mark);
        std::stringstream revoke;
        revoke << "UPDATE refresh_token SET revoked_at = time::now() WHERE user = '" << drogon::utils::escapeHtml(userId) << "';";
        db.exec(revoke.str());
        std::stringstream revokeSessions;
        revokeSessions << "UPDATE session SET revoked_at = time::now() WHERE user = '" << drogon::utils::escapeHtml(userId) << "';";
        db.exec(revokeSessions.str());
        writeAudit(db, "auth.password_reset", userId);
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k204NoContent);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "auth", __LINE__, "reset failed", "POST", e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","reset failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void AuthController::verifyEmail(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "AuthController";
    auto json = req->getJsonObject();
    if (!json || !json->isMember("code")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","code required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    auto code = (*json)["code"].asString();
    try {
        SurrealClient db;
        std::stringstream ss;
        ss << "SELECT * FROM email_verification WHERE code = '" << drogon::utils::escapeHtml(code) << "' LIMIT 1;";
        auto res = db.exec(ss.str());
        Json::Value record;
        if (res.isArray() && res.size() > 0 && res[0]["result"].isArray() && res[0]["result"].size() > 0) {
            record = res[0]["result"][0];
        }
        if (record.isNull()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","invalid code"}});
            resp->setStatusCode(k400BadRequest);
            return callback(resp);
        }
        auto expires = record.get("expires_at", "").asString();
        auto nowIso = isoTimestamp(std::chrono::system_clock::now());
        if (!expires.empty() && nowIso > expires) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","code expired"}});
            resp->setStatusCode(k400BadRequest);
            return callback(resp);
        }
        auto userId = record.get("user", "").asString();
        Json::Value update;
        update["email_verified"] = true;
        db.mergeRecord("user", userId, update);
        Json::Value mark;
        mark["verified_at"] = isoTimestamp(std::chrono::system_clock::now());
        db.mergeRecord("email_verification", record["id"].asString(), mark);
        writeAudit(db, "auth.email_verified", userId);
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k204NoContent);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "auth", __LINE__, "verify email failed", "POST", e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","verify failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void AuthController::jwks(const HttpRequestPtr&, std::function<void (const HttpResponsePtr &)> &&callback) {
    Json::Value jwk;
    jwk["kty"] = "oct";
    jwk["kid"] = "primary";
    jwk["use"] = "sig";
    jwk["alg"] = "HS256";
    auto secret = getJwtSecret();
    jwk["k"] = drogon::utils::base64Encode(secret);
    Json::Value body(Json::objectValue);
    body["keys"] = Json::Value(Json::arrayValue);
    body["keys"].append(jwk);
    auto resp = HttpResponse::newHttpJsonResponse(body);
    callback(resp);
}

void AuthController::startTotpEnrollment(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "AuthController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto userId = claims.get("sub", "").asString();
    try {
        SurrealClient db;
        auto user = db.selectById("user", userId);
        if (user.isNull()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","user not found"}});
            resp->setStatusCode(k404NotFound);
            return callback(resp);
        }
        auto secret = totp::generate_secret();
        Json::Value update;
        update["pending_totp_secret"] = secret;
        db.mergeRecord("user", userId, update);
        Json::Value out;
        out["secret"] = secret;
        out["otpauth"] = totp::otpauth_uri(secret, user.get("email", "").asString(), "DragonBreath");
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "auth", __LINE__, "totp enable failed", "POST", e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","enable failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void AuthController::verifyTotpEnrollment(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "AuthController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto userId = claims.get("sub", "").asString();
    auto json = req->getJsonObject();
    if (!json || !json->isMember("code")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","code required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    auto code = (*json)["code"].asString();
    try {
        SurrealClient db;
        auto user = db.selectById("user", userId);
        auto pending = user.get("pending_totp_secret", "").asString();
        if (pending.empty() || !totp::verify(pending, code)) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","invalid code"}});
            resp->setStatusCode(k400BadRequest);
            return callback(resp);
        }
        auto codes = totp::generate_backup_codes();
        auto hashed = hashCodes(codes);
        Json::Value hashedArr(Json::arrayValue);
        for (const auto& c : hashed) hashedArr.append(c);
        Json::Value update;
        update["totp_secret"] = pending;
        update["totp_enabled"] = true;
        update["pending_totp_secret"] = Json::nullValue;
        update["totp_backup_codes"] = hashedArr;
        db.mergeRecord("user", userId, update);
        writeAudit(db, "auth.totp_enabled", userId);
        Json::Value out;
        Json::Value codesArr(Json::arrayValue);
        for (const auto& c : codes) codesArr.append(c);
        out["backup_codes"] = codesArr;
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "auth", __LINE__, "totp verify failed", "POST", e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","verify failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void AuthController::disableTotp(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "AuthController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto userId = claims.get("sub", "").asString();
    auto json = req->getJsonObject();
    auto code = json ? (*json).get("code", "").asString() : std::string();
    try {
        SurrealClient db;
        auto user = db.selectById("user", userId);
        if (!user.get("totp_enabled", false).asBool()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","totp not enabled"}});
            resp->setStatusCode(k400BadRequest);
            return callback(resp);
        }
        bool ok = false;
        auto secret = user.get("totp_secret", "").asString();
        if (!secret.empty() && !code.empty()) {
            ok = totp::verify(secret, code);
        }
        if (!ok && json && json->isMember("backup_code")) {
            ok = consumeBackupCode(db, user, (*json)["backup_code"].asString());
        }
        if (!ok) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","invalid code"}});
            resp->setStatusCode(k400BadRequest);
            return callback(resp);
        }
        Json::Value update;
        update["totp_secret"] = Json::nullValue;
        update["totp_enabled"] = false;
        update["totp_backup_codes"] = Json::arrayValue;
        db.mergeRecord("user", userId, update);
        writeAudit(db, "auth.totp_disabled", userId);
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k204NoContent);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "auth", __LINE__, "totp disable failed", "POST", e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","disable failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void AuthController::generateBackupCodes(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "AuthController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto userId = claims.get("sub", "").asString();
    try {
        SurrealClient db;
        auto user = db.selectById("user", userId);
        if (!user.get("totp_enabled", false).asBool()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","totp not enabled"}});
            resp->setStatusCode(k400BadRequest);
            return callback(resp);
        }
        auto codes = totp::generate_backup_codes();
        auto hashed = hashCodes(codes);
        Json::Value hashedArr(Json::arrayValue);
        for (const auto& c : hashed) hashedArr.append(c);
        Json::Value update;
        update["totp_backup_codes"] = hashedArr;
        db.mergeRecord("user", userId, update);
        Json::Value out;
        Json::Value arr(Json::arrayValue);
        for (const auto& c : codes) arr.append(c);
        out["backup_codes"] = arr;
        writeAudit(db, "auth.backup_codes_regenerated", userId);
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "auth", __LINE__, "backup codes failed", "POST", e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","generation failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}
