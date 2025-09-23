#pragma once
#include <string>
#include <vector>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sstream>
#include <iomanip>

namespace crypto {

inline std::string to_hex(const std::vector<unsigned char>& v) {
    std::ostringstream oss;
    for (auto b : v) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
}
inline std::vector<unsigned char> from_hex(const std::string& s) {
    std::vector<unsigned char> out;
    for (size_t i=0; i<s.size(); i+=2) {
        std::string byteString = s.substr(i,2);
        unsigned char byte = (unsigned char) strtol(byteString.c_str(), nullptr, 16);
        out.push_back(byte);
    }
    return out;
}

inline void random_bytes(unsigned char* buf, size_t n) { RAND_bytes(buf, (int)n); }

inline std::string sha256_hex(const std::string& data) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }
    std::vector<unsigned char> hash(EVP_MAX_MD_SIZE);
    unsigned int len = 0;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, hash.data(), &len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("sha256 computation failed");
    }
    EVP_MD_CTX_free(ctx);
    return to_hex(std::vector<unsigned char>(hash.begin(), hash.begin() + len));
}

inline std::string random_token_hex(size_t bytes = 32) {
    std::vector<unsigned char> buf(bytes);
    random_bytes(buf.data(), buf.size());
    return to_hex(buf);
}

inline std::string random_alphanum(size_t length) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::vector<unsigned char> buf(length);
    random_bytes(buf.data(), buf.size());
    std::string out;
    out.reserve(length);
    for (auto b : buf) {
        out.push_back(alphabet[b % (sizeof(alphabet) - 1)]);
    }
    return out;
}

inline std::string hash_password_pbkdf2(const std::string& password, int iterations = 150000) {
    unsigned char salt[16];
    random_bytes(salt, sizeof(salt));
    std::vector<unsigned char> dk(32);
    PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(), salt, sizeof(salt),
                      iterations, EVP_sha256(), (int)dk.size(), dk.data());
    std::vector<unsigned char> saltv(salt, salt+sizeof(salt));
    // format: pbkdf2$<iter>$<salt_hex>$<dk_hex>
    return "pbkdf2$" + std::to_string(iterations) + "$" + to_hex(saltv) + "$" + to_hex(dk);
}

inline bool verify_password_pbkdf2(const std::string& password, const std::string& stored) {
    // parse
    // pbkdf2$iter$salt_hex$dk_hex
    auto a = stored.find('$'); if (a==std::string::npos) return false;
    auto b = stored.find('$', a+1); if (b==std::string::npos) return false;
    auto c = stored.find('$', b+1); if (c==std::string::npos) return false;
    int iter = std::stoi(stored.substr(a+1, b-a-1));
    auto salt_hex = stored.substr(b+1, c-b-1);
    auto dk_hex = stored.substr(c+1);
    auto salt = from_hex(salt_hex);
    auto dk_expected = from_hex(dk_hex);
    std::vector<unsigned char> dk(32);
    PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(), salt.data(), (int)salt.size(),
                      iter, EVP_sha256(), (int)dk.size(), dk.data());
    // constant-time compare
    if (dk.size() != dk_expected.size()) return false;
    unsigned char diff = 0;
    for (size_t i=0;i<dk.size();++i) diff |= dk[i] ^ dk_expected[i];
    return diff == 0;
}

} // namespace crypto
