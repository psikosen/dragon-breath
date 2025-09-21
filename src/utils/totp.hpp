#pragma once
#include "crypto.hpp"
#include <openssl/hmac.h>
#include <cmath>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <iomanip>
#include <iterator>
#include <string>
#include <vector>
#include <ctime>

namespace totp {

inline std::string base32_encode(const std::vector<unsigned char>& data) {
    static const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string out;
    int buffer = 0;
    int bitsLeft = 0;
    for (auto byte : data) {
        buffer = (buffer << 8) | byte;
        bitsLeft += 8;
        while (bitsLeft >= 5) {
            out.push_back(alphabet[(buffer >> (bitsLeft - 5)) & 0x1F]);
            bitsLeft -= 5;
        }
    }
    if (bitsLeft > 0) {
        out.push_back(alphabet[(buffer << (5 - bitsLeft)) & 0x1F]);
    }
    return out;
}

inline std::vector<unsigned char> base32_decode(const std::string& encoded) {
    static bool init = false;
    static int table[256];
    if (!init) {
        std::fill(std::begin(table), std::end(table), -1);
        std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        for (size_t i = 0; i < alphabet.size(); ++i) {
            table[static_cast<int>(alphabet[i])] = static_cast<int>(i);
        }
        init = true;
    }
    int buffer = 0;
    int bitsLeft = 0;
    std::vector<unsigned char> out;
    for (char ch : encoded) {
        if (ch == '=') break;
        int val = table[static_cast<int>(std::toupper(ch))];
        if (val < 0) continue;
        buffer = (buffer << 5) | val;
        bitsLeft += 5;
        if (bitsLeft >= 8) {
            out.push_back(static_cast<unsigned char>((buffer >> (bitsLeft - 8)) & 0xFF));
            bitsLeft -= 8;
        }
    }
    return out;
}

inline std::string generate_secret(size_t bytes = 20) {
    std::vector<unsigned char> buf(bytes);
    crypto::random_bytes(buf.data(), buf.size());
    return base32_encode(buf);
}

inline uint32_t hotp(const std::string& secret, uint64_t counter) {
    auto key = base32_decode(secret);
    unsigned char msg[8];
    for (int i = 7; i >= 0; --i) {
        msg[i] = static_cast<unsigned char>(counter & 0xFF);
        counter >>= 8;
    }
    unsigned int len = 0;
    unsigned char hmac[EVP_MAX_MD_SIZE];
    HMAC(EVP_sha1(), key.data(), static_cast<int>(key.size()), msg, sizeof(msg), hmac, &len);
    int offset = hmac[len - 1] & 0x0F;
    uint32_t binary = ((hmac[offset] & 0x7F) << 24) |
                      ((hmac[offset + 1] & 0xFF) << 16) |
                      ((hmac[offset + 2] & 0xFF) << 8) |
                      (hmac[offset + 3] & 0xFF);
    return binary % 1000000;
}

inline bool verify(const std::string& secret, const std::string& code, int window = 1, int step = 30) {
    if (secret.empty() || code.size() < 6) return false;
    uint64_t now = static_cast<uint64_t>(std::time(nullptr) / step);
    uint32_t codeInt = static_cast<uint32_t>(std::stoi(code));
    for (int i = -window; i <= window; ++i) {
        uint32_t generated = hotp(secret, now + i);
        if (generated == codeInt) {
            return true;
        }
    }
    return false;
}

inline std::string generate_code(const std::string& secret, int step = 30) {
    uint64_t counter = static_cast<uint64_t>(std::time(nullptr) / step);
    uint32_t value = hotp(secret, counter);
    std::ostringstream oss;
    oss << std::setw(6) << std::setfill('0') << value;
    return oss.str();
}

inline std::string otpauth_uri(const std::string& secret, const std::string& email, const std::string& issuer) {
    return "otpauth://totp/" + drogon::utils::urlEncode(issuer + ":" + email) +
           "?secret=" + secret + "&issuer=" + drogon::utils::urlEncode(issuer) + "&algorithm=SHA1&digits=6&period=30";
}

inline std::vector<std::string> generate_backup_codes(size_t count = 10) {
    std::vector<std::string> codes;
    codes.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        auto token = crypto::random_token(5);
        codes.push_back(token.substr(0, 10));
    }
    return codes;
}

} // namespace totp
