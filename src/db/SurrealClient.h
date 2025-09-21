#pragma once
#include <drogon/drogon.h>

class SurrealClient {
public:
    SurrealClient();

    // Executes a SurrealQL query (single or multiple statements).
    // Returns parsed JSON array (result sets) or throws on error.
    Json::Value exec(const std::string& surql);

    // Convenience helpers
    Json::Value selectOneByEmail(const std::string& emailNorm);
    Json::Value createUser(const std::string& email, const std::string& emailNorm,
                           const std::string& passwordHash, const std::string& role);
    Json::Value selectById(const std::string& table, const std::string& id);
    Json::Value createRecord(const std::string& table, const Json::Value& content);
    Json::Value mergeRecord(const std::string& table, const std::string& id, const Json::Value& content);
    Json::Value softDelete(const std::string& table, const std::string& id);
    Json::Value listWithQuery(const std::string& query);

private:
    std::string sanitizeId(const std::string& id);
    drogon::HttpClientPtr client_;
    std::string ns_;
    std::string db_;
    std::string basicAuth_;
};
