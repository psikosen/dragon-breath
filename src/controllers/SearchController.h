#pragma once
#include <drogon/HttpController.h>

class SearchController : public drogon::HttpController<SearchController> {
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(SearchController::search, "/api/search", drogon::Get, "AuthFilter");
    METHOD_LIST_END

    void search(const drogon::HttpRequestPtr& req, std::function<void (const drogon::HttpResponsePtr &)> &&callback);
};
