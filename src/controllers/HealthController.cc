#include "HealthController.h"
#include <drogon/drogon.h>
#include "../db/SurrealClient.h"
#include "../utils/logging.hpp"
#include <memory>
#include <string>

using namespace drogon;

namespace {
struct HealthState {
    bool dbOk{false};
    bool redisOk{false};
    std::string dbError;
    std::string redisError;
};

constexpr const char kClassName[] = "HealthController";
}

void HealthController::health(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    auto state = std::make_shared<HealthState>();
    try {
        SurrealClient db;
        db.exec("SELECT 1;");
        state->dbOk = true;
    } catch (const std::exception& e) {
        state->dbOk = false;
        state->dbError = e.what();
        logging::error(__FILE__, kClassName, __func__, "health", __LINE__, "database check failed", req->getMethodString(), e.what(), "post");
    }

    auto cbPtr = std::make_shared<std::function<void (const HttpResponsePtr &)>>(
        std::move(callback));
    auto finish = [state, cbPtr, req](bool redisOk, const std::string& redisError) {
        state->redisOk = redisOk;
        state->redisError = redisError;
        bool healthy = state->dbOk && state->redisOk;

        Json::Value services(Json::objectValue);
        Json::Value db(Json::objectValue);
        db["healthy"] = state->dbOk;
        if (!state->dbOk && !state->dbError.empty()) {
            db["error"] = state->dbError;
        }
        services["database"] = db;

        Json::Value redis(Json::objectValue);
        redis["healthy"] = state->redisOk;
        if (!state->redisOk && !state->redisError.empty()) {
            redis["error"] = state->redisError;
        }
        services["redis"] = redis;

        Json::Value body(Json::objectValue);
        body["services"] = services;
        body["status"] = healthy ? "ok" : "degraded";

        auto resp = HttpResponse::newHttpJsonResponse(body);
        if (!healthy) {
            resp->setStatusCode(k503ServiceUnavailable);
            std::string detail;
            if (!state->dbOk && !state->dbError.empty()) {
                detail += "db:" + state->dbError;
            }
            if (!state->redisOk && !state->redisError.empty()) {
                if (!detail.empty()) detail += "; ";
                detail += "redis:" + state->redisError;
            }
            logging::error(__FILE__, kClassName, __func__, "health", __LINE__, "health degraded", req->getMethodString(), detail, "post");
        } else {
            logging::info(__FILE__, kClassName, __func__, "health", __LINE__, "health ok", req->getMethodString(), "", "post");
        }
        (*cbPtr)(resp);
    };

    auto redisClient = app().getRedisClient();
    if (!redisClient) {
        finish(false, "redis unavailable");
        return;
    }

    redisClient->execCommandAsync(
        [finish](const drogon::nosql::RedisResult &){
            finish(true, "");
        },
        [finish](const std::exception &e){
            finish(false, e.what());
        },
        "PING");
}
