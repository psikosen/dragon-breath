#include "WebhookController.h"
#include <drogon/drogon.h>
#include "../db/SurrealClient.h"
#include "../utils/logging.hpp"
#include <sstream>
#include <regex>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <stdexcept>

using namespace drogon;

namespace {
Json::Value sanitizeWebhook(Json::Value hook) {
    return hook;
}

Json::Value ensureWebhook(SurrealClient& db, const std::string& id) {
    auto hook = db.selectById("webhook", id);
    if (hook.isNull()) {
        throw std::runtime_error("webhook not found");
    }
    return hook;
}

bool canAccess(const Json::Value& hook, const Json::Value& claims) {
    if (claims.get("role","user").asString() == "admin") return true;
    return hook.get("created_by", "").asString() == claims.get("sub", "").asString();
}

std::string isoNow() {
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *gmtime(&tt);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

struct ParsedUrl {
    std::string scheme;
    std::string host;
    unsigned short port;
    std::string path;
    bool valid{false};
};

ParsedUrl parseUrl(const std::string& url) {
    std::regex re(R"((https?)://([^/]+)(/.*)?$)");
    std::smatch match;
    ParsedUrl parsed;
    if (std::regex_match(url, match, re)) {
        parsed.scheme = match[1];
        std::string hostPort = match[2];
        parsed.path = match[3].str().empty() ? "/" : match[3].str();
        auto pos = hostPort.find(':');
        if (pos != std::string::npos) {
            parsed.host = hostPort.substr(0, pos);
            parsed.port = static_cast<unsigned short>(std::stoi(hostPort.substr(pos+1)));
        } else {
            parsed.host = hostPort;
            parsed.port = parsed.scheme == "https" ? 443 : 80;
        }
        parsed.valid = true;
    }
    return parsed;
}

} // namespace

void WebhookController::listWebhooks(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "WebhookController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto userId = claims.get("sub", "").asString();
    try {
        SurrealClient db;
        std::stringstream ss;
        if (claims.get("role","user").asString() == "admin") {
            ss << "SELECT * FROM webhook WHERE deleted_at = NONE ORDER BY created_at DESC;";
        } else {
            ss << "SELECT * FROM webhook WHERE created_by = '" << drogon::utils::escapeHtml(userId) << "' AND deleted_at = NONE ORDER BY created_at DESC;";
        }
        auto res = db.exec(ss.str());
        Json::Value out;
        out["webhooks"] = Json::Value(Json::arrayValue);
        if (res.isArray() && res.size() > 0) {
            for (const auto& row : res[0]["result"]) {
                out["webhooks"].append(sanitizeWebhook(row));
            }
        }
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "webhooks", __LINE__, "list failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","query failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void WebhookController::createWebhook(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "WebhookController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto json = req->getJsonObject();
    if (!json || !json->isMember("url")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","url required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    try {
        SurrealClient db;
        Json::Value rec;
        rec["url"] = (*json)["url"].asString();
        rec["created_by"] = claims.get("sub", "").asString();
        if (json->isMember("events")) rec["events"] = (*json)["events"];
        if (json->isMember("secret")) rec["secret"] = (*json)["secret"];
        if (json->isMember("org")) rec["org"] = (*json)["org"];
        if (json->isMember("description")) rec["description"] = (*json)["description"];
        auto hook = db.createRecord("webhook", rec);
        Json::Value out;
        out["webhook"] = sanitizeWebhook(hook);
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "webhooks", __LINE__, "create failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","create failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void WebhookController::getWebhook(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& id) {
    constexpr auto className = "WebhookController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    try {
        SurrealClient db;
        auto hook = ensureWebhook(db, id);
        if (!canAccess(hook, claims)) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
            resp->setStatusCode(k403Forbidden);
            return callback(resp);
        }
        Json::Value out;
        out["webhook"] = sanitizeWebhook(hook);
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","not found"}});
        resp->setStatusCode(k404NotFound);
        callback(resp);
    }
}

void WebhookController::updateWebhook(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& id) {
    constexpr auto className = "WebhookController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto json = req->getJsonObject();
    if (!json) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","body required"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    try {
        SurrealClient db;
        auto hook = ensureWebhook(db, id);
        if (!canAccess(hook, claims)) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
            resp->setStatusCode(k403Forbidden);
            return callback(resp);
        }
        Json::Value update(Json::objectValue);
        if (json->isMember("url")) update["url"] = (*json)["url"];
        if (json->isMember("events")) update["events"] = (*json)["events"];
        if (json->isMember("secret")) update["secret"] = (*json)["secret"];
        if (json->isMember("description")) update["description"] = (*json)["description"];
        if (update.getMemberNames().empty()) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","no fields"}});
            resp->setStatusCode(k400BadRequest);
            return callback(resp);
        }
        update["updated_at"] = isoNow();
        auto updated = db.mergeRecord("webhook", id, update);
        Json::Value out;
        out["webhook"] = sanitizeWebhook(updated);
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "webhooks", __LINE__, "update failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","update failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void WebhookController::deleteWebhook(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& id) {
    constexpr auto className = "WebhookController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    try {
        SurrealClient db;
        auto hook = ensureWebhook(db, id);
        if (!canAccess(hook, claims)) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
            resp->setStatusCode(k403Forbidden);
            return callback(resp);
        }
        Json::Value update;
        update["deleted_at"] = isoNow();
        db.mergeRecord("webhook", id, update);
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k204NoContent);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "webhooks", __LINE__, "delete failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","delete failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void WebhookController::testWebhook(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& id) {
    constexpr auto className = "WebhookController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    try {
        SurrealClient db;
        auto hook = ensureWebhook(db, id);
        if (!canAccess(hook, claims)) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
            resp->setStatusCode(k403Forbidden);
            return callback(resp);
        }
        auto url = hook.get("url", "").asString();
        auto parsed = parseUrl(url);
        if (!parsed.valid) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","invalid url"}});
            resp->setStatusCode(k400BadRequest);
            return callback(resp);
        }
        bool useSSL = parsed.scheme == "https";
        auto client = HttpClient::newHttpClient(parsed.host, parsed.port, useSSL);
        auto reqOut = HttpRequest::newHttpJsonRequest(Json::Value{{"event","test"},{"webhook_id", id},{"timestamp", isoNow()}});
        reqOut->setMethod(Post);
        reqOut->setPath(parsed.path);
        auto [result, respMsg] = client->sendRequest(reqOut);
        Json::Value out;
        out["result"] = (result == ReqResult::Ok && respMsg && respMsg->getStatusCode() < 500) ? "success" : "failed";
        if (respMsg) {
            out["status"] = respMsg->getStatusCode();
        } else {
            out["status"] = Json::Value();
        }
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "webhooks", __LINE__, "test failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","test failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}
