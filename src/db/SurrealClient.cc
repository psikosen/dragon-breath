#include "SurrealClient.h"
#include <drogon/drogon.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <cctype>

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

static Json::Value firstRow(const Json::Value& res) {
    if (res.isArray() && res.size() > 0 && res[0]["result"].isArray() && res[0]["result"].size() > 0) {
        return res[0]["result"][0];
    }
    return Json::Value(Json::nullValue);
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
    return firstRow(res);
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
    auto row = firstRow(res);
    if (!row.isNull()) {
        return row;
    }
    throw std::runtime_error("Failed to create user");
}

std::string SurrealClient::sanitizeId(const std::string& id) {
    std::string out;
    out.reserve(id.size());
    for (char c : id) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == ':') {
            out.push_back(c);
        }
    }
    if (out.empty()) {
        throw std::runtime_error("Invalid id");
    }
    return out;
}

Json::Value SurrealClient::selectById(const std::string& table, const std::string& id) {
    auto safeId = sanitizeId(id);
    std::stringstream ss;
    if (safeId.rfind(table + ":", 0) == 0) {
        ss << "SELECT * FROM " << table << " WHERE id = '" << drogon::utils::escapeHtml(safeId) << "' LIMIT 1;";
    } else {
        ss << "SELECT * FROM " << table << " WHERE id = " << table << ":'" << drogon::utils::escapeHtml(safeId) << "' LIMIT 1;";
    }
    auto res = exec(ss.str());
    return firstRow(res);
}

Json::Value SurrealClient::createRecord(const std::string& table, const Json::Value& content) {
    std::stringstream ss;
    ss << "CREATE " << table << " CONTENT " << drogon::utils::toString(content) << ";";
    auto res = exec(ss.str());
    auto row = firstRow(res);
    if (!row.isNull()) return row;
    throw std::runtime_error("Failed to create record");
}

Json::Value SurrealClient::mergeRecord(const std::string& table, const std::string& id, const Json::Value& content) {
    auto safeId = sanitizeId(id);
    std::stringstream ss;
    if (safeId.rfind(table + ":", 0) == 0) {
        ss << "UPDATE '" << drogon::utils::escapeHtml(safeId) << "' MERGE " << drogon::utils::toString(content) << ";";
    } else {
        ss << "UPDATE " << table << ":'" << drogon::utils::escapeHtml(safeId) << "' MERGE " << drogon::utils::toString(content) << ";";
    }
    auto res = exec(ss.str());
    return firstRow(res);
}

Json::Value SurrealClient::softDelete(const std::string& table, const std::string& id) {
    auto safeId = sanitizeId(id);
    std::stringstream ss;
    std::string target;
    if (safeId.rfind(table + ":", 0) == 0) {
        target = "'" + drogon::utils::escapeHtml(safeId) + "'";
    } else {
        target = table + ":'" + drogon::utils::escapeHtml(safeId) + "'";
    }
    ss << "UPDATE " << target << " MERGE { status: 'disabled', deleted_at: time::now() };";
    auto res = exec(ss.str());
    return firstRow(res);
}

Json::Value SurrealClient::listWithQuery(const std::string& query) {
    return exec(query);
}
