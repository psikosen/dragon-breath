#include "AuthController.h"
#include <drogon/drogon.h>
#include "../db/SurrealClient.h"
#include "../utils/crypto.hpp"
#include "../utils/jwt.hpp"

using namespace drogon;

static std::string toLowerTrim(std::string s){
    // trim
    auto isspace2 = [](unsigned char c){return std::isspace(c);};
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [&](unsigned char c){return !isspace2(c);}));
    s.erase(std::find_if(s.rbegin(), s.rend(), [&](unsigned char c){return !isspace2(c);}).base(), s.end());
    // lower
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){return std::tolower(c);});
    return s;
}

void AuthController::registerUser(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    auto json = req->getJsonObject();
    if (!json || !(*json).isMember("email") || !(*json).isMember("password")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{ {"error","email and password required"} });
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    auto email = (*json)["email"].asString();
    auto pass  = (*json)["password"].asString();
    if (pass.size() < 8) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{ {"error","password too short"} });
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    try {
        SurrealClient db;
        auto emailNorm = toLowerTrim(email);
        auto existing = db.selectOneByEmail(emailNorm);
        if (!existing.isNull()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{ {"error","email already exists"} });
            resp->setStatusCode(k409Conflict);
            return callback(resp);
        }
        auto hash = crypto::hash_password_pbkdf2(pass);
        auto user = db.createUser(email, emailNorm, hash, "admin"); // first user can be admin in dev
        // token
        Json::Value claims;
        claims["sub"] = user["id"].asString();
        claims["email"] = emailNorm;
        claims["role"] = user.get("role","user").asString();
        claims["iat"] = (Json::Int64)std::time(nullptr);
        claims["exp"] = (Json::Int64)(std::time(nullptr) + 3600*12);
        claims["jti"] = drogon::utils::getUuid().c_str();
        const char* sec = std::getenv("JWT_SECRET");
        std::string secret = sec ? sec : "change_me_dev_secret";
        auto token = jwt::create_hs256(claims, secret);

        Json::Value out;
        out["token"] = token;
        out["user"] = user;
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{ {"error","registration failed"} });
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void AuthController::login(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    auto json = req->getJsonObject();
    if (!json || !(*json).isMember("email") || !(*json).isMember("password")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{ {"error","email and password required"} });
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    auto emailNorm = toLowerTrim((*json)["email"].asString());
    auto pass = (*json)["password"].asString();
    try {
        SurrealClient db;
        auto user = db.selectOneByEmail(emailNorm);
        if (user.isNull()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{ {"error","invalid credentials"} });
            resp->setStatusCode(k401Unauthorized);
            return callback(resp);
        }
        auto stored = user.get("password_hash","").asString();
        if (!crypto::verify_password_pbkdf2(pass, stored)) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{ {"error","invalid credentials"} });
            resp->setStatusCode(k401Unauthorized);
            return callback(resp);
        }
        Json::Value claims;
        claims["sub"] = user["id"].asString();
        claims["email"] = emailNorm;
        claims["role"] = user.get("role","user").asString();
        claims["iat"] = (Json::Int64)std::time(nullptr);
        claims["exp"] = (Json::Int64)(std::time(nullptr) + 3600*12);
        claims["jti"] = drogon::utils::getUuid().c_str();
        const char* sec = std::getenv("JWT_SECRET");
        std::string secret = sec ? sec : "change_me_dev_secret";
        auto token = jwt::create_hs256(claims, secret);

        Json::Value out;
        out["token"] = token;
        out["user"] = user;
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{ {"error","login failed"} });
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void AuthController::logout(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    // Add jti to blacklist with TTL
    auto attrs = req->getAttributes();
    if (!attrs->find("claims")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{ {"error","no claims"} });
        resp->setStatusCode(k401Unauthorized);
        return callback(resp);
    }
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto jti = claims.get("jti","").asString();
    auto exp = claims.get("exp", (Json::Int64)std::time(nullptr)).asInt64();
    auto now = (Json::Int64)std::time(nullptr);
    auto ttl = (int)std::max<Json::Int64>(0, exp - now);

    auto redis = app().getRedisClient();
    redis->execCommandAsync(
        [callback](const drogon::nosql::RedisResult &){ 
            auto resp = HttpResponse::newHttpResponse();
            resp->setStatusCode(k204NoContent);
            callback(resp);
        },
        [callback](const std::exception &e){
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{ {"error","redis error"} });
            resp->setStatusCode(k500InternalServerError);
            callback(resp);
        },
        "SETEX blacklist:jti:%s %d 1", jti.c_str(), ttl);
}
