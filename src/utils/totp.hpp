#pragma once

#include "crypto.hpp"
#include <openssl/hmac.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <drogon/utils/Utilities.h>

namespace totp {

inline std::string base32_encode(const std::vector<unsigned char>& data) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string out;
    size_t i = 0;
    int current = 0;
    int bits = 0;
    while (i < data.size()) {
        current = (current << 8) | data[i++];
        bits += 8;
        while (bits >= 5) {
            int index = (current >> (bits - 5)) & 0x1F;
            out.push_back(alphabet[index]);
            bits -= 5;
        }
    }
    if (bits > 0) {
        int index = (current << (5 - bits)) & 0x1F;
        out.push_back(alphabet[index]);
    }
    while (out.size() % 8 != 0) {
        out.push_back('=');
    }
    return out;
}

inline std::vector<unsigned char> base32_decode(const std::string& input) {
    static const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::vector<unsigned char> out;
    int buffer = 0;
    int bits = 0;
    for (char c : input) {
        if (c == '=') break;
        char up = std::toupper(static_cast<unsigned char>(c));
        auto pos = alphabet.find(up);
        if (pos == std::string::npos) {
            throw std::runtime_error("invalid base32 character");
        }
        buffer = (buffer << 5) | static_cast<int>(pos);
        bits += 5;
        if (bits >= 8) {
            int shift = bits - 8;
            out.push_back(static_cast<unsigned char>((buffer >> shift) & 0xFF));
            bits -= 8;
            buffer &= (1 << bits) - 1;
        }
    }
    return out;
}

inline std::string generate_secret(size_t bytes = 20) {
    std::vector<unsigned char> buf(bytes);
    crypto::random_bytes(buf.data(), buf.size());
    return base32_encode(buf);
}

inline uint32_t compute_code(const std::vector<unsigned char>& key, uint64_t counter) {
    unsigned char counter_bytes[8];
    for (int i = 7; i >= 0; --i) {
        counter_bytes[i] = static_cast<unsigned char>(counter & 0xFF);
        counter >>= 8;
    }
    unsigned int len = 0;
    unsigned char digest[EVP_MAX_MD_SIZE];
    if (!HMAC(EVP_sha1(), key.data(), static_cast<int>(key.size()), counter_bytes, sizeof(counter_bytes), digest, &len)) {
        throw std::runtime_error("HMAC failed");
    }
    int offset = digest[len - 1] & 0x0F;
    uint32_t binary = ((digest[offset] & 0x7F) << 24) |
                      ((digest[offset + 1] & 0xFF) << 16) |
                      ((digest[offset + 2] & 0xFF) << 8) |
                      (digest[offset + 3] & 0xFF);
    return binary % 1000000;
}

inline bool verify_code(const std::string& secret, const std::string& code, int window = 1, int digits = 6, int period = 30) {
    if (code.size() != static_cast<size_t>(digits)) {
        return false;
    }
    for (char c : code) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    auto key = base32_decode(secret);
    auto now = std::chrono::system_clock::now();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    uint64_t current_counter = static_cast<uint64_t>(seconds) / period;
    uint32_t target = static_cast<uint32_t>(std::stoul(code));
    for (int i = -window; i <= window; ++i) {
        uint64_t counter = current_counter + i;
        uint32_t candidate = compute_code(key, counter);
        if (candidate == target) {
            return true;
        }
    }
    return false;
}

inline std::string otpauth_uri(const std::string& issuer, const std::string& accountName, const std::string& secret) {
    std::string label = drogon::utils::urlEncode(issuer + ":" + accountName);
    std::string encIssuer = drogon::utils::urlEncode(issuer);
    return "otpauth://totp/" + label + "?secret=" + secret + "&issuer=" + encIssuer + "&algorithm=SHA1&digits=6&period=30";
}

inline std::string generate_code_now(const std::string& secret, int period = 30) {
    auto key = base32_decode(secret);
    auto now = std::chrono::system_clock::now();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    uint32_t code = compute_code(key, static_cast<uint64_t>(seconds) / period);
    std::ostringstream oss;
    oss << std::setw(6) << std::setfill('0') << code;
    return oss.str();
}

} // namespace totp
