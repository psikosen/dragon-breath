#pragma once
#include <drogon/HttpController.h>

class FileController : public drogon::HttpController<FileController> {
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(FileController::upload, "/api/files/upload", drogon::Post, "AuthFilter");
    ADD_METHOD_TO(FileController::listFiles, "/api/files", drogon::Get, "AuthFilter");
    ADD_METHOD_TO(FileController::getFile, "/api/files/{1}", drogon::Get, "AuthFilter");
    ADD_METHOD_TO(FileController::deleteFile, "/api/files/{1}", drogon::Delete, "AuthFilter");
    METHOD_LIST_END

    void upload(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void listFiles(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
    void getFile(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback, const std::string& id);
    void deleteFile(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback, const std::string& id);
};
