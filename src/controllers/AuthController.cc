#include "AuthController.h"
#include <drogon/drogon.h>
#include "../db/SurrealClient.h"
#include "../utils/crypto.hpp"
#include "../utils/jwt.hpp"
#include "../utils/totp.hpp"
#include "../utils/logging.hpp"
#include <optional>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <ctime>

using namespace drogon;

namespace {
std::string toLowerTrim(std::string s) {
    auto isspace2 = [](unsigned char c) { return std::isspace(c); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [&](unsigned char c) { return !isspace2(c); }));
    s.erase(std::find_if(s.rbegin(), s.rend(), [&](unsigned char c) { return !isspace2(c); }).base(), s.end());
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

std::string isoTime(std::chrono::system_clock::time_point tp) {
    auto tt = std::chrono::system_clock::to_time_t(tp);
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

std::string recordIdPart(const std::string& rid) {
    auto pos = rid.find(':');
    if (pos == std::string::npos) {
        return rid;
    }
    return rid.substr(pos + 1);
}

Json::Value sanitizeUser(Json::Value user) {
    user.removeMember("password_hash");
    user.removeMember("totp_secret");
    user.removeMember("backup_codes");
    return user;
}

void audit(SurrealClient& db,
           const std::string& userId,
           const std::string& action,
           const std::string& resourceType,
           const std::string& resourceId,
           const Json::Value& metadata = Json::Value(Json::objectValue)) {
    Json::Value metaCopy = metadata;
    db.recordAudit(userId, action, resourceType, resourceId, metaCopy);
}

std::string peerIp(const HttpRequestPtr& req) {
    auto forwarded = req->getHeader("X-Forwarded-For");
    if (!forwarded.empty()) {
        auto pos = forwarded.find(',');
        std::string candidate = forwarded.substr(0, pos);
        candidate.erase(0, candidate.find_first_not_of(" \t"));
        candidate.erase(candidate.find_last_not_of(" \t") + 1);
        return candidate;
    }
    try {
        return req->getPeerAddr().toIp();
    } catch (...) {
        return "";
    }
}

std::string methodName(const HttpRequestPtr& req) {
    switch (req->getMethod()) {
        case Get: return "GET";
        case Post: return "POST";
        case Put: return "PUT";
        case Delete: return "DELETE";
        case Patch: return "PATCH";
        default: return "NONE";
    }
}

bool consumeBackupCode(SurrealClient& db, Json::Value& user, const std::string& code) {
    if (!user.isMember("backup_codes") || !user["backup_codes"].isArray()) {
        return false;
    }
    Json::Value remaining(Json::arrayValue);
    bool matched = false;
    for (const auto& entry : user["backup_codes"]) {
        std::string stored = entry.asString();
        if (!matched && crypto::verify_password_pbkdf2(code, stored)) {
            matched = true;
            continue;
        }
        remaining.append(stored);
    }
    if (matched) {
        Json::Value update;
        update["backup_codes"] = remaining;
        db.updateRecord("user", recordIdPart(user["id"].asString()), update);
        user["backup_codes"] = remaining;
    }
    return matched;
}

std::string base64Url(const std::string& input) {
    auto encoded = drogon::utils::base64Encode(input);
    encoded.erase(std::remove(encoded.begin(), encoded.end(), '='), encoded.end());
    std::replace(encoded.begin(), encoded.end(), '+', '-');
    std::replace(encoded.begin(), encoded.end(), '/', '_');
    return encoded;
}

Json::Value issueTokens(SurrealClient& db,
                        Json::Value user,
                        const HttpRequestPtr& req,
                        const std::optional<std::string>& existingSession = std::nullopt,
                        bool updateLogin = false) {
    auto now = std::chrono::system_clock::now();
    std::string sessionRecordId;
    if (existingSession.has_value()) {
        sessionRecordId = *existingSession;
        Json::Value update;
        update["last_seen_at"] = isoTime(now);
        db.updateRecord("session", recordIdPart(sessionRecordId), update);
    } else {
        Json::Value session;
        session["user_id"] = user["id"].asString();
        auto ua = req->getHeader("User-Agent");
        if (!ua.empty()) {
            session["user_agent"] = ua;
        }
        auto ip = peerIp(req);
        if (!ip.empty()) {
            session["ip_address"] = ip;
        }
        auto created = db.createRecord("session", drogon::utils::getUuid(), session);
        sessionRecordId = created["id"].asString();
    }

    auto accessLifetime = std::chrono::seconds(3600 * 12);
    auto refreshLifetime = std::chrono::hours(24 * 14);

    Json::Value claims;
    claims["sub"] = user["id"].asString();
    claims["email"] = user.get("email", "").asString();
    claims["role"] = user.get("role", "user").asString();
    claims["iat"] = static_cast<Json::Int64>(std::time(nullptr));
    claims["exp"] = static_cast<Json::Int64>(std::time(nullptr) + accessLifetime.count());
    claims["jti"] = drogon::utils::getUuid();
    claims["sid"] = sessionRecordId;

    const char* sec = std::getenv("JWT_SECRET");
    std::string secret = sec ? sec : "change_me_dev_secret";
    auto accessToken = jwt::create_hs256(claims, secret);

    std::string refreshPlain = crypto::random_token_hex(32);
    Json::Value refreshPayload;
    refreshPayload["user_id"] = user["id"].asString();
    refreshPayload["session_id"] = sessionRecordId;
    refreshPayload["token_hash"] = crypto::sha256_hex(refreshPlain);
    refreshPayload["active"] = true;
    refreshPayload["expires_at"] = isoTime(now + refreshLifetime);
    db.createRecord("refresh_token", drogon::utils::getUuid(), refreshPayload);

    if (updateLogin) {
        Json::Value update;
        update["last_login_at"] = isoTime(now);
        db.updateRecord("user", recordIdPart(user["id"].asString()), update);
    }

    logging::info("AuthController.cc", "AuthController", "issueTokens", "auth", __LINE__, "issued tokens", methodName(req));

    Json::Value out;
    out["access_token"] = accessToken;
    out["refresh_token"] = refreshPlain;
    out["expires_in"] = static_cast<Json::Int64>(accessLifetime.count());
    out["refresh_token_expires_at"] = refreshPayload["expires_at"];
    out["session_id"] = sessionRecordId;
    out["user"] = sanitizeUser(user);
    return out;
}

} // namespace

void AuthController::registerUser(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)> &&callback) {
    auto json = req->getJsonObject();
    if (!json || !(*json).isMember("email") || !(*json).isMember("password")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "email and password required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }

    auto email = (*json)["email"].asString();
    auto pass = (*json)["password"].asString();
    if (pass.size() < 8) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "password too short"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }

    try {
        SurrealClient db;
        auto emailNorm = toLowerTrim(email);
        auto existing = db.selectOneByEmail(emailNorm);
        if (!existing.isNull()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "email already exists"}});
            resp->setStatusCode(k409Conflict);
            return callback(resp);
        }

        bool firstUser = false;
        try {
            auto countRes = db.exec("SELECT count() AS total FROM user;");
            if (countRes.isArray() && !countRes.empty() && countRes[0]["result"].isArray() && !countRes[0]["result"].empty()) {
                firstUser = countRes[0]["result"][0]["total"].asInt64() == 0;
            }
        } catch (...) {
            firstUser = false;
        }

        auto hash = crypto::hash_password_pbkdf2(pass);
        auto user = db.createUser(email, emailNorm, hash, firstUser ? "admin" : "user");
        Json::Value update;
        update["email_verified"] = false;
        update["status"] = "active";
        db.updateRecord("user", recordIdPart(user["id"].asString()), update);
        user = db.selectById("user", recordIdPart(user["id"].asString()));

        auto verificationCode = crypto::random_token_hex(16);
        Json::Value verification;
        verification["user_id"] = user["id"].asString();
        verification["code_hash"] = crypto::sha256_hex(verificationCode);
        verification["expires_at"] = isoTime(std::chrono::system_clock::now() + std::chrono::hours(24));
        db.createRecord("email_verification", drogon::utils::getUuid(), verification);

        auto tokens = issueTokens(db, user, req, std::nullopt, true);
        tokens["verification_code"] = verificationCode;

        audit(db, user["id"].asString(), "register", "user", user["id"].asString(), Json::Value{{"email", emailNorm}});

        auto resp = HttpResponse::newHttpJsonResponse(tokens);
        resp->setStatusCode(k201Created);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error("AuthController.cc", "AuthController", "registerUser", "auth", __LINE__, e.what(), methodName(req), e.what());
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "registration failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void AuthController::login(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)> &&callback) {
    auto json = req->getJsonObject();
    if (!json || !(*json).isMember("email") || !(*json).isMember("password")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "email and password required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }

    auto emailNorm = toLowerTrim((*json)["email"].asString());
    auto pass = (*json)["password"].asString();

    try {
        SurrealClient db;
        auto user = db.selectOneByEmail(emailNorm);
        if (user.isNull()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "invalid credentials"}});
            resp->setStatusCode(k401Unauthorized);
            return callback(resp);
        }
        if (user.get("status", "active").asString() != "active") {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "account disabled"}});
            resp->setStatusCode(k403Forbidden);
            return callback(resp);
        }

        auto stored = user.get("password_hash", "").asString();
        if (!crypto::verify_password_pbkdf2(pass, stored)) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "invalid credentials"}});
            resp->setStatusCode(k401Unauthorized);
            return callback(resp);
        }

        bool totpEnabled = user.get("totp_enabled", false).asBool();
        if (totpEnabled) {
            std::string totpCode = (*json).get("totp", "").asString();
            std::string backup = (*json).get("backup_code", "").asString();
            bool ok = false;
            auto secret = user.get("totp_secret", "").asString();
            if (!secret.empty() && !totpCode.empty()) {
                ok = totp::verify_code(secret, totpCode);
            }
            if (!ok && !backup.empty()) {
                ok = consumeBackupCode(db, user, backup);
            }
            if (!ok) {
                auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "totp required"}});
                resp->setStatusCode(k401Unauthorized);
                return callback(resp);
            }
        }

        auto tokens = issueTokens(db, user, req, std::nullopt, true);
        audit(db, user["id"].asString(), "login", "session", tokens["session_id"].asString(), Json::Value{{"ip", peerIp(req)}});

        auto resp = HttpResponse::newHttpJsonResponse(tokens);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error("AuthController.cc", "AuthController", "login", "auth", __LINE__, e.what(), methodName(req), e.what());
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "login failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void AuthController::logout(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)> &&callback) {
    auto attrs = req->getAttributes();
    if (!attrs->find("claims")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "no claims"}});
        resp->setStatusCode(k401Unauthorized);
        return callback(resp);
    }
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto jti = claims.get("jti", "").asString();
    auto exp = claims.get("exp", static_cast<Json::Int64>(std::time(nullptr))).asInt64();
    auto now = static_cast<Json::Int64>(std::time(nullptr));
    auto ttl = static_cast<int>(std::max<Json::Int64>(0, exp - now));

    try {
        auto redis = app().getRedisClient();
        redis->execCommandAsync(
            [callback](const drogon::nosql::RedisResult &) {
                auto resp = HttpResponse::newHttpResponse();
                resp->setStatusCode(k204NoContent);
                callback(resp);
            },
            [callback](const std::exception &) {
                auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "redis error"}});
                resp->setStatusCode(k500InternalServerError);
                callback(resp);
            },
            "SETEX blacklist:jti:%s %d 1", jti.c_str(), ttl);

        SurrealClient db;
        auto sessionId = claims.get("sid", "").asString();
        if (!sessionId.empty()) {
            Json::Value update;
            update["revoked"] = true;
            update["last_seen_at"] = isoTime(std::chrono::system_clock::now());
            db.updateRecord("session", recordIdPart(sessionId), update);
            std::stringstream ss;
            ss << "UPDATE refresh_token SET active = false, rotated_at = time::now() WHERE session_id = '" << sessionId << "';";
            db.exec(ss.str());
            audit(db, claims.get("sub", "").asString(), "logout", "session", sessionId, Json::Value());
        }
    } catch (const std::exception& e) {
        logging::error("AuthController.cc", "AuthController", "logout", "auth", __LINE__, e.what(), methodName(req), e.what());
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "logout failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void AuthController::refresh(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)> &&callback) {
    auto json = req->getJsonObject();
    if (!json || !(*json).isMember("refresh_token")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "refresh_token required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    auto token = (*json)["refresh_token"].asString();
    if (token.empty()) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "invalid refresh token"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }

    try {
        SurrealClient db;
        auto hash = crypto::sha256_hex(token);
        std::stringstream ss;
        ss << "LET $hash := '" << hash << "';";
        ss << "SELECT * FROM refresh_token WHERE token_hash = $hash AND active = true AND expires_at > time::now() LIMIT 1;";
        auto res = db.exec(ss.str());
        auto tokenRecord = db.firstResult(res);
        if (tokenRecord.isNull()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "refresh expired"}});
            resp->setStatusCode(k401Unauthorized);
            return callback(resp);
        }
        auto sessionId = tokenRecord.get("session_id", "").asString();
        auto session = db.selectById("session", recordIdPart(sessionId));
        if (session.isNull() || session.get("revoked", false).asBool()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "session revoked"}});
            resp->setStatusCode(k401Unauthorized);
            return callback(resp);
        }
        auto userId = tokenRecord.get("user_id", "").asString();
        auto user = db.selectById("user", recordIdPart(userId));
        if (user.isNull() || user.get("status", "active").asString() != "active") {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "account disabled"}});
            resp->setStatusCode(k401Unauthorized);
            return callback(resp);
        }

        Json::Value update;
        update["active"] = false;
        update["rotated_at"] = isoTime(std::chrono::system_clock::now());
        db.updateRecord("refresh_token", recordIdPart(tokenRecord["id"].asString()), update);

        auto tokens = issueTokens(db, user, req, sessionId, false);
        audit(db, userId, "refresh", "session", sessionId, Json::Value());

        auto resp = HttpResponse::newHttpJsonResponse(tokens);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error("AuthController.cc", "AuthController", "refresh", "auth", __LINE__, e.what(), methodName(req), e.what());
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "refresh failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void AuthController::forgotPassword(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)> &&callback) {
    auto json = req->getJsonObject();
    if (!json || !(*json).isMember("email")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"status", "ok"}});
        resp->setStatusCode(k200OK);
        return callback(resp);
    }
    auto emailNorm = toLowerTrim((*json)["email"].asString());

    try {
        SurrealClient db;
        auto user = db.selectOneByEmail(emailNorm);
        std::string resetToken;
        if (!user.isNull()) {
            resetToken = crypto::random_token_hex(16);
            Json::Value reset;
            reset["user_id"] = user["id"].asString();
            reset["token_hash"] = crypto::sha256_hex(resetToken);
            reset["expires_at"] = isoTime(std::chrono::system_clock::now() + std::chrono::hours(1));
            db.createRecord("password_reset", drogon::utils::getUuid(), reset);
            audit(db, user["id"].asString(), "password_forgot", "user", user["id"].asString(), Json::Value());
        }
        Json::Value out;
        out["status"] = "ok";
        if (!resetToken.empty()) {
            out["reset_token"] = resetToken;
        }
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error("AuthController.cc", "AuthController", "forgotPassword", "auth", __LINE__, e.what(), methodName(req), e.what());
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void AuthController::resetPassword(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)> &&callback) {
    auto json = req->getJsonObject();
    if (!json || !(*json).isMember("token") || !(*json).isMember("password")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "token and password required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }

    auto token = (*json)["token"].asString();
    auto password = (*json)["password"].asString();
    if (password.size() < 8) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "password too short"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }

    try {
        SurrealClient db;
        auto hash = crypto::sha256_hex(token);
        std::stringstream ss;
        ss << "LET $hash := '" << hash << "';";
        ss << "SELECT * FROM password_reset WHERE token_hash = $hash AND used = false AND expires_at > time::now() LIMIT 1;";
        auto res = db.exec(ss.str());
        auto resetRecord = db.firstResult(res);
        if (resetRecord.isNull()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "invalid token"}});
            resp->setStatusCode(k400BadRequest);
            return callback(resp);
        }

        auto userId = resetRecord.get("user_id", "").asString();
        Json::Value update;
        update["password_hash"] = crypto::hash_password_pbkdf2(password);
        update["profile_updated_at"] = isoTime(std::chrono::system_clock::now());
        db.updateRecord("user", recordIdPart(userId), update);

        Json::Value mark;
        mark["used"] = true;
        db.updateRecord("password_reset", recordIdPart(resetRecord["id"].asString()), mark);

        std::stringstream revoke;
        revoke << "UPDATE refresh_token SET active = false, rotated_at = time::now() WHERE user_id = '" << userId << "';";
        db.exec(revoke.str());

        audit(db, userId, "password_reset", "user", userId, Json::Value());

        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"status", "ok"}});
        callback(resp);
    } catch (const std::exception& e) {
        logging::error("AuthController.cc", "AuthController", "resetPassword", "auth", __LINE__, e.what(), methodName(req), e.what());
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "reset failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void AuthController::verifyEmail(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)> &&callback) {
    auto json = req->getJsonObject();
    if (!json || !(*json).isMember("code")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "code required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    auto code = (*json)["code"].asString();

    try {
        SurrealClient db;
        auto hash = crypto::sha256_hex(code);
        std::stringstream ss;
        ss << "LET $hash := '" << hash << "';";
        ss << "SELECT * FROM email_verification WHERE code_hash = $hash AND used = false AND expires_at > time::now() LIMIT 1;";
        auto res = db.exec(ss.str());
        auto record = db.firstResult(res);
        if (record.isNull()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "invalid code"}});
            resp->setStatusCode(k400BadRequest);
            return callback(resp);
        }
        auto userId = record.get("user_id", "").asString();
        Json::Value update;
        update["email_verified"] = true;
        db.updateRecord("user", recordIdPart(userId), update);

        Json::Value mark;
        mark["used"] = true;
        db.updateRecord("email_verification", recordIdPart(record["id"].asString()), mark);

        audit(db, userId, "verify_email", "user", userId, Json::Value());

        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"status", "ok"}});
        callback(resp);
    } catch (const std::exception& e) {
        logging::error("AuthController.cc", "AuthController", "verifyEmail", "auth", __LINE__, e.what(), methodName(req), e.what());
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "verify failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void AuthController::jwks(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)> &&callback) {
    const char* sec = std::getenv("JWT_SECRET");
    std::string secret = sec ? sec : "change_me_dev_secret";
    auto kid = crypto::sha256_hex(secret).substr(0, 16);
    Json::Value key;
    key["kty"] = "oct";
    key["kid"] = kid;
    key["k"] = base64Url(secret);
    key["alg"] = "HS256";
    key["use"] = "sig";
    Json::Value jwks;
    jwks["keys"].append(key);
    auto resp = HttpResponse::newHttpJsonResponse(jwks);
    callback(resp);
}

void AuthController::totpEnable(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)> &&callback) {
    auto attrs = req->getAttributes();
    if (!attrs->find("claims")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "no claims"}});
        resp->setStatusCode(k401Unauthorized);
        return callback(resp);
    }
    Json::Value claims = attrs->get<Json::Value>("claims");
    try {
        SurrealClient db;
        auto user = db.selectById("user", recordIdPart(claims.get("sub", "").asString()));
        if (user.isNull()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "user not found"}});
            resp->setStatusCode(k404NotFound);
            return callback(resp);
        }
        auto secret = totp::generate_secret();
        Json::Value update;
        update["totp_secret"] = secret;
        update["totp_enabled"] = false;
        db.updateRecord("user", recordIdPart(user["id"].asString()), update);
        auto uri = totp::otpauth_uri("DragonBreath", user.get("email", "user").asString(), secret);
        audit(db, user["id"].asString(), "totp_enable_start", "user", user["id"].asString(), Json::Value());
        Json::Value out;
        out["secret"] = secret;
        out["otpauth"] = uri;
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error("AuthController.cc", "AuthController", "totpEnable", "auth", __LINE__, e.what(), methodName(req), e.what());
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "enable failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void AuthController::totpVerify(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)> &&callback) {
    auto attrs = req->getAttributes();
    if (!attrs->find("claims")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "no claims"}});
        resp->setStatusCode(k401Unauthorized);
        return callback(resp);
    }
    auto json = req->getJsonObject();
    if (!json || !(*json).isMember("code")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "code required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    auto code = (*json)["code"].asString();
    Json::Value claims = attrs->get<Json::Value>("claims");
    try {
        SurrealClient db;
        auto user = db.selectById("user", recordIdPart(claims.get("sub", "").asString()));
        if (user.isNull()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "user not found"}});
            resp->setStatusCode(k404NotFound);
            return callback(resp);
        }
        auto secret = user.get("totp_secret", "").asString();
        if (secret.empty() || !totp::verify_code(secret, code)) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "invalid code"}});
            resp->setStatusCode(k400BadRequest);
            return callback(resp);
        }
        Json::Value update;
        update["totp_enabled"] = true;
        db.updateRecord("user", recordIdPart(user["id"].asString()), update);
        audit(db, user["id"].asString(), "totp_verified", "user", user["id"].asString(), Json::Value());
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"status", "ok"}});
        callback(resp);
    } catch (const std::exception& e) {
        logging::error("AuthController.cc", "AuthController", "totpVerify", "auth", __LINE__, e.what(), methodName(req), e.what());
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "verify failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void AuthController::totpDisable(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)> &&callback) {
    auto attrs = req->getAttributes();
    if (!attrs->find("claims")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "no claims"}});
        resp->setStatusCode(k401Unauthorized);
        return callback(resp);
    }
    auto json = req->getJsonObject();
    std::string code = json ? (*json).get("code", "").asString() : "";
    std::string backup = json ? (*json).get("backup_code", "").asString() : "";
    Json::Value claims = attrs->get<Json::Value>("claims");
    try {
        SurrealClient db;
        auto user = db.selectById("user", recordIdPart(claims.get("sub", "").asString()));
        if (user.isNull()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "user not found"}});
            resp->setStatusCode(k404NotFound);
            return callback(resp);
        }
        if (!user.get("totp_enabled", false).asBool()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"status", "ok"}});
            return callback(resp);
        }
        bool ok = false;
        auto secret = user.get("totp_secret", "").asString();
        if (!secret.empty() && !code.empty()) {
            ok = totp::verify_code(secret, code);
        }
        if (!ok && !backup.empty()) {
            ok = consumeBackupCode(db, user, backup);
        }
        if (!ok) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "verification required"}});
            resp->setStatusCode(k401Unauthorized);
            return callback(resp);
        }
        Json::Value update;
        update["totp_secret"] = Json::Value(Json::nullValue);
        update["totp_enabled"] = false;
        update["backup_codes"] = Json::Value(Json::arrayValue);
        db.updateRecord("user", recordIdPart(user["id"].asString()), update);
        audit(db, user["id"].asString(), "totp_disabled", "user", user["id"].asString(), Json::Value());
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"status", "ok"}});
        callback(resp);
    } catch (const std::exception& e) {
        logging::error("AuthController.cc", "AuthController", "totpDisable", "auth", __LINE__, e.what(), methodName(req), e.what());
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "disable failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void AuthController::backupCodes(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)> &&callback) {
    auto attrs = req->getAttributes();
    if (!attrs->find("claims")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "no claims"}});
        resp->setStatusCode(k401Unauthorized);
        return callback(resp);
    }
    auto json = req->getJsonObject();
    std::string code = json ? (*json).get("code", "").asString() : "";
    Json::Value claims = attrs->get<Json::Value>("claims");
    try {
        SurrealClient db;
        auto user = db.selectById("user", recordIdPart(claims.get("sub", "").asString()));
        if (user.isNull()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "user not found"}});
            resp->setStatusCode(k404NotFound);
            return callback(resp);
        }
        if (!user.get("totp_enabled", false).asBool()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "totp not enabled"}});
            resp->setStatusCode(k400BadRequest);
            return callback(resp);
        }
        auto secret = user.get("totp_secret", "").asString();
        if (secret.empty() || !totp::verify_code(secret, code)) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "verification required"}});
            resp->setStatusCode(k401Unauthorized);
            return callback(resp);
        }
        Json::Value codes(Json::arrayValue);
        Json::Value hashed(Json::arrayValue);
        for (int i = 0; i < 8; ++i) {
            auto c = crypto::random_alphanum(10);
            codes.append(c);
            hashed.append(crypto::hash_password_pbkdf2(c));
        }
        Json::Value update;
        update["backup_codes"] = hashed;
        db.updateRecord("user", recordIdPart(user["id"].asString()), update);
        audit(db, user["id"].asString(), "backup_codes", "user", user["id"].asString(), Json::Value());
        Json::Value out;
        out["codes"] = codes;
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error("AuthController.cc", "AuthController", "backupCodes", "auth", __LINE__, e.what(), methodName(req), e.what());
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error", "generation failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}
