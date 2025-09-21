#include "FileController.h"
#include <drogon/drogon.h>
#include "../db/SurrealClient.h"
#include "../utils/logging.hpp"
#include "../utils/crypto.hpp"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <stdexcept>

using namespace drogon;

namespace {
std::string storageRoot() {
    const char* root = std::getenv("FILE_STORAGE_ROOT");
    return root ? std::string(root) : std::string("storage/files");
}

std::string isoNow() {
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *gmtime(&tt);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

Json::Value sanitizeFile(Json::Value file) {
    return file;
}

Json::Value ensureFile(SurrealClient& db, const std::string& id) {
    auto file = db.selectById("file_asset", id);
    if (file.isNull()) {
        throw std::runtime_error("file not found");
    }
    return file;
}

} // namespace

void FileController::upload(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "FileController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto userId = claims.get("sub", "").asString();
    auto files = req->getFiles();
    if (files.empty()) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","no files"}});
        resp->setStatusCode(k400BadRequest);
        return callback(resp);
    }
    try {
        std::filesystem::create_directories(storageRoot());
        SurrealClient db;
        Json::Value uploaded(Json::arrayValue);
        for (const auto& file : files) {
            auto uuid = drogon::utils::getUuid();
            auto key = uuid + "_" + file.getFileName();
            auto path = std::filesystem::path(storageRoot()) / key;
            file.saveTo(path.string());
            Json::Value rec;
            rec["owner"] = userId;
            rec["filename"] = file.getFileName();
            rec["storage_key"] = key;
            rec["mime_type"] = file.getContentType();
            rec["size"] = static_cast<Json::Int64>(std::filesystem::file_size(path));
            std::ifstream ifs(path, std::ios::binary);
            std::ostringstream oss;
            oss << ifs.rdbuf();
            rec["checksum"] = crypto::sha256_hex(oss.str());
            auto record = db.createRecord("file_asset", rec);
            uploaded.append(sanitizeFile(record));
        }
        Json::Value out;
        out["files"] = uploaded;
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "files", __LINE__, "upload failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","upload failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void FileController::listFiles(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
    constexpr auto className = "FileController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto userId = claims.get("sub", "").asString();
    try {
        SurrealClient db;
        std::stringstream ss;
        ss << "SELECT * FROM file_asset WHERE owner = '" << drogon::utils::escapeHtml(userId) << "' ORDER BY created_at DESC LIMIT 100;";
        auto res = db.exec(ss.str());
        Json::Value out;
        out["files"] = Json::Value(Json::arrayValue);
        if (res.isArray() && res.size() > 0) {
            for (const auto& row : res[0]["result"]) {
                out["files"].append(sanitizeFile(row));
            }
        }
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "files", __LINE__, "list failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","query failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}

void FileController::getFile(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& id) {
    constexpr auto className = "FileController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto userId = claims.get("sub", "").asString();
    try {
        SurrealClient db;
        auto file = ensureFile(db, id);
        if (file.get("owner", "").asString() != userId) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
            resp->setStatusCode(k403Forbidden);
            return callback(resp);
        }
        Json::Value out;
        out["file"] = sanitizeFile(file);
        auto resp = HttpResponse::newHttpJsonResponse(out);
        callback(resp);
    } catch (const std::exception& e) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","not found"}});
        resp->setStatusCode(k404NotFound);
        callback(resp);
    }
}

void FileController::deleteFile(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& id) {
    constexpr auto className = "FileController";
    auto attrs = req->getAttributes();
    Json::Value claims = attrs->get<Json::Value>("claims");
    auto userId = claims.get("sub", "").asString();
    try {
        SurrealClient db;
        auto file = ensureFile(db, id);
        if (file.get("owner", "").asString() != userId) {
            auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","forbidden"}});
            resp->setStatusCode(k403Forbidden);
            return callback(resp);
        }
        auto key = file.get("storage_key", "").asString();
        std::filesystem::path path = std::filesystem::path(storageRoot()) / key;
        if (std::filesystem::exists(path)) {
            std::filesystem::remove(path);
        }
        std::stringstream ss;
        ss << "DELETE file_asset WHERE id = '" << drogon::utils::escapeHtml(id) << "';";
        db.exec(ss.str());
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k204NoContent);
        callback(resp);
    } catch (const std::exception& e) {
        logging::error(__FILE__, className, __func__, "files", __LINE__, "delete failed", req->getMethodString(), e.what(), "post");
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value{{"error","delete failed"}});
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
    }
}
