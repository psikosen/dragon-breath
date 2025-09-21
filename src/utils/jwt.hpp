#pragma once
#include <string>
#include <vector>
#include <stdexcept>
#include <ctime>
#include <drogon/drogon.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

// Minimal HS256 JWT (create + verify).
// Not a complete implementation, but sufficient for access tokens.
// Dependencies: OpenSSL, Drogon for Json.

namespace jwt {

inline std::string b64url_encode(const std::string& in) {
    // Standard base64
    static const char b64_table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val=0, valb=-6;
    for (uint8_t c : in) {
        val = (val<<8) + c;
        valb += 8;
        while (valb>=0) {
            out.push_back(b64_table[(val>>valb)&0x3F]);
            valb-=6;
        }
    }
    if (valb>-6) out.push_back(b64_table[((val<<8)>>(valb+8))&0x3F]);
    while (out.size()%4) out.push_back('=');
    // URL-safe
    for (auto& ch : out) { if (ch=='+') ch='-'; else if (ch=='/') ch='_'; }
    while (!out.empty() && out.back()=='=') out.pop_back();
    return out;
}

inline std::string b64url_decode(const std::string& in) {
    std::string s = in;
    for (auto& ch : s) { if (ch=='-') ch='+'; else if (ch=='_') ch='/'; }
    while (s.size()%4) s.push_back('=');
    BIO* bio, *b64;
    char* buffer = (char*)malloc(s.size());
    memset(buffer, 0, s.size());
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_mem_buf(s.data(), s.size());
    bio = BIO_push(b64, bio);
    int len = BIO_read(bio, buffer, s.size());
    BIO_free_all(bio);
    std::string out(buffer, len > 0 ? len : 0);
    free(buffer);
    return out;
}

inline std::string hmac_sha256(const std::string& key, const std::string& data) {
    unsigned int len = EVP_MAX_MD_SIZE;
    unsigned char out[EVP_MAX_MD_SIZE];
    HMAC(EVP_sha256(), key.data(), (int)key.size(),
         (const unsigned char*)data.data(), (int)data.size(), out, &len);
    return std::string((char*)out, len);
}

inline std::string sign_hs256(const std::string& secret, const std::string& header_payload) {
    auto sig = hmac_sha256(secret, header_payload);
    return b64url_encode(sig);
}

inline std::string create_hs256(const Json::Value& payload, const std::string& secret) {
    Json::Value header;
    header["alg"] = "HS256";
    header["typ"] = "JWT";
    auto h = drogon::utils::toString(header);
    auto p = drogon::utils::toString(payload);
    std::string token = b64url_encode(h) + "." + b64url_encode(p);
    token += "." + sign_hs256(secret, token);
    return token;
}

inline Json::Value verify_hs256(const std::string& token, const std::string& secret) {
    auto dot1 = token.find('.');
    auto dot2 = token.find('.', dot1+1);
    if (dot1 == std::string::npos || dot2 == std::string::npos) {
        throw std::runtime_error("Invalid token");
    }
    std::string h64 = token.substr(0, dot1);
    std::string p64 = token.substr(dot1+1, dot2 - dot1 - 1);
    std::string s64 = token.substr(dot2+1);

    std::string data = h64 + "." + p64;
    auto expected = sign_hs256(secret, data);
    if (expected != s64) {
        throw std::runtime_error("Invalid signature");
    }
    auto payloadStr = b64url_decode(p64);
    Json::Value payload;
    Json::CharReaderBuilder rbuilder;
    std::string errs;
    std::unique_ptr<Json::CharReader> reader(rbuilder.newCharReader());
    if (!reader->parse(payloadStr.data(), payloadStr.data() + payloadStr.size(), &payload, &errs)) {
        throw std::runtime_error("Invalid payload JSON");
    }
    // exp check
    if (payload.isMember("exp")) {
        auto now = (Json::Int64)std::time(nullptr);
        if (payload["exp"].asInt64() < now) throw std::runtime_error("Token expired");
    }
    return payload;
}

} // namespace jwt
