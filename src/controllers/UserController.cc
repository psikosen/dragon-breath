#include "UserController.h"
#include <drogon/drogon.h>
#include "../db/SurrealClient.h"

using namespace drogon;

static bool isAdminClaims(const Json::Value& claims) {
    return claims.get("role","user").asString() == "admin";
}

void UserController::me(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    // Try cached profile
    auto redis = app().getRedisClient();
    auto uid = claims.get("sub","").asString();
    redis->execCommandAsync(
        [callback, uid](const drogon::nosql::RedisResult &r){
            if (r.type() != drogon::nosql::RedisResultType::kNil) {
                // cached JSON
                Json::Value user;
                Json::CharReaderBuilder rb;
                std::string errs;
                auto s = r.asString();
                std::unique_ptr<Json::CharReader> reader(rb.newCharReader());
                if (reader->parse(s.data(), s.data()+s.size(), &user, &errs)) {
                    Json::Value out;
                    out["user"] = user;
                    auto resp = HttpResponse::newHttpJsonResponse(out);
                    return callback(resp);
                }
            }
            // not cached -> fetch from DB by email
            try {
                SurrealClient db;
                // we only stored email in claims; reselect by email
                auto email = claims.get("email","").asString();
                auto user = db.selectOneByEmail(email);
                Json::Value out;
                out["user"] = user;
                auto resp = HttpResponse::newHttpJsonResponse(out);
                callback(resp);
                // set cache async (no wait)
                app().getRedisClient()->execCommandAsync(
                    [](const drogon::nosql::RedisResult &){},
                    [](const std::exception &){}, 
                    "SETEX cache:user:%s %d %s",
                    uid.c_str(), 300, drogon::utils::toString(user).c_str());
            } catch (...) {
                auto resp = HttpResponse::newHttpJsonResponse(Json::Value{ {"error","lookup failed"} });
                resp->setStatusCode(k500InternalServerError);
                callback(resp);
            }
        },
        [callback](const std::exception &e){
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{ {"error","redis error"} });
            resp->setStatusCode(k500InternalServerError);
            callback(resp);
        },
        "GET cache:user:%s", uid.c_str());
}

void UserController::listUsers(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    if (!isAdminClaims(claims)) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{ {"error","forbidden"} });
        resp->setStatusCode(k403Forbidden);
        return callback(resp);
    }
    try {
        SurrealClient db;
        auto res = db.exec("SELECT id, email, role, created_at, updated_at FROM user ORDER BY created_at DESC LIMIT 100;");
        Json::Value out;
        out["result_sets"] = res;
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (...) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{ {"error","query failed"} });
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}
