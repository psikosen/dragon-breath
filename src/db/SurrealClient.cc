#include "SurrealClient.h"
#include <drogon/drogon.h>
#include <string>
#include <sstream>
#include <iomanip>

using namespace drogon;

static std::string b64(const std::string& in) {
    static const char b[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    size_t val=0, valb=-6;
    for (uint8_t c : in) {
        val = (val<<8) + c;
        valb += 8;
        while (valb>=0) {
            out.push_back(b[(val>>valb)&0x3F]);
            valb-=6;
        }
    }
    if (valb>-6) out.push_back(b[((val<<8)>>(valb+8))&0x3F]);
    while (out.size()%4) out.push_back('=');
    return out;
}

SurrealClient::SurrealClient() {
    const char* url = std::getenv("SURREAL_URL");
    const char* ns = std::getenv("SURREAL_NS");
    const char* db = std::getenv("SURREAL_DB");
    const char* user = std::getenv("SURREAL_USER");
    const char* pass = std::getenv("SURREAL_PASS");
    std::string base = url ? url : "http://127.0.0.1:8000";
    client_ = HttpClient::newHttpClient(base);
    ns_ = ns ? ns : "app";
    db_ = db ? db : "dashboard";
    std::string up = std::string(user ? user : "root") + ":" + std::string(pass ? pass : "root");
    basicAuth_ = "Basic " + b64(up);
}

Json::Value SurrealClient::exec(const std::string& surql) {
    auto req = HttpRequest::newHttpRequest();
    req->setMethod(Post);
    req->setPath("/sql");
    req->addHeader("Accept","application/json");
    req->addHeader("Surreal-NS", ns_);
    req->addHeader("Surreal-DB", db_);
    req->addHeader("Authorization", basicAuth_);
    req->setBody(surql);

    auto [result, resp] = client_->sendRequest(req);
    if (result != ReqResult::Ok || !resp) {
        throw std::runtime_error("SurrealDB request failed");
    }
    auto json = resp->getJsonObject();
    if (!json) {
        throw std::runtime_error("SurrealDB: invalid JSON");
    }
    return *json;
}

Json::Value SurrealClient::selectOneByEmail(const std::string& emailNorm) {
    std::stringstream ss;
    ss << "LET $email := string::lower(string::trim('" << drogon::utils::escapeHtml(emailNorm) << "'));"
       << "SELECT * FROM user WHERE email_norm = $email LIMIT 1;";
    auto res = exec(ss.str());
    if (res.isArray() && res.size() > 0 && res[0]["result"].isArray() && res[0]["result"].size() > 0) {
        return res[0]["result"][0];
    }
    return Json::Value(Json::nullValue);
}

Json::Value SurrealClient::createUser(const std::string& email, const std::string& emailNorm,
                                      const std::string& passwordHash, const std::string& role) {
    std::stringstream ss;
    ss << "CREATE user SET "
       << "email = '" << drogon::utils::escapeHtml(email) << "', "
       << "email_norm = '" << drogon::utils::escapeHtml(emailNorm) << "', "
       << "password_hash = '" << drogon::utils::escapeHtml(passwordHash) << "', "
       << "role = '" << drogon::utils::escapeHtml(role) << "';";
    auto res = exec(ss.str());
    if (res.isArray() && res.size() > 0 && res[0]["result"].isArray() && res[0]["result"].size() > 0) {
        return res[0]["result"][0];
    }
    throw std::runtime_error("Failed to create user");
}
