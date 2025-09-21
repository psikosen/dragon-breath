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

private:
    drogon::HttpClientPtr client_;
    std::string ns_;
    std::string db_;
    std::string basicAuth_;
};
