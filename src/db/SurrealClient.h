#pragma once
#include <drogon/drogon.h>
#include <json/value.h>
#include <json/writer.h>

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
    Json::Value createRecord(const std::string& table, const std::string& id, const Json::Value& content);
    Json::Value updateRecord(const std::string& table, const std::string& id, const Json::Value& content);
    void recordAudit(const std::string& userId,
                     const std::string& action,
                     const std::string& resourceType,
                     const std::string& resourceId,
                     const Json::Value& metadata);
    Json::Value firstResult(const Json::Value& resultSets) const;

private:
    drogon::HttpClientPtr client_;
    std::string ns_;
    std::string db_;
    std::string basicAuth_;

    std::string toJsonString(const Json::Value& value) const;
};
