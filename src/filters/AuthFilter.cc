#include "AuthFilter.h"
#include <drogon/drogon.h>
#include "../utils/jwt.hpp"

using namespace drogon;

void AuthFilter::doFilter(const HttpRequestPtr& req, FilterCallback &&fcb, FilterChainCallback &&fccb) {
    auto auth = req->getHeader("Authorization");
    if (auth.rfind("Bearer ", 0) != 0) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{ {"error","missing bearer token"} });
        resp->setStatusCode(k401Unauthorized);
        return fcb(resp);
    }
    std::string token = auth.substr(7);
    try {
        const char* sec = std::getenv("JWT_SECRET");
        std::string secret = sec ? sec : "change_me_dev_secret";
        Json::Value claims = jwt::verify_hs256(token, secret);
        // blacklist check via Redis
        auto redis = app().getRedisClient();
        bool blacklisted = false;
        std::string jti = claims.get("jti","").asString();
        if (!jti.empty()) {
            redis->execCommandAsync(
                [&, fcb, fccb, req, claims](const drogon::nosql::RedisResult &r) mutable {
                    if (r.type() != drogon::nosql::RedisResultType::kNil) {
                        // key exists => blacklisted
                        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{ {"error","token revoked"} });
                        resp->setStatusCode(k401Unauthorized);
                        return fcb(resp);
                    } else {
                        // inject claims
                        req->getAttributes()->insert("claims", claims);
                        fccb();
                    }
                },
                [fcb](const std::exception &e){
                    auto resp = HttpResponse::newHttpJsonResponse(Json::Value{ {"error","redis error"} });
                    resp->setStatusCode(k500InternalServerError);
                    fcb(resp);
                },
                "GET blacklist:jti:%s", jti.c_str());
            return; // async branch
        }
        // no jti -> proceed
        req->getAttributes()->insert("claims", claims);
        fccb();
    } catch (const std::exception& e) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{ {"error","invalid token"} });
        resp->setStatusCode(k401Unauthorized);
        fcb(resp);
    }
}
