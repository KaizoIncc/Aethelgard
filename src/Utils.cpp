// Utils.cpp - Optimized internal implementation (no API changes)
// Based on original uploaded file. Original: Utils.cpp. :contentReference[oaicite:1]{index=1}

#include "Utils.hpp"
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <algorithm>
#include <mutex>
#include <unordered_map>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

// ---------------------------- Internal helpers & caches ----------------------------
namespace {

    static mutex g_cache_mutex;
    static unordered_map<string, string> g_pubkey_cache;   // privateKeyBase64 -> publicKeyBase64
    static unordered_map<string, string> g_addr_cache;     // publicKeyBase64 -> address hex
    static unordered_map<string, EC_KEY*> g_eckey_cache;        // privateKeyBase64 -> EC_KEY*
    static unordered_map<string, EC_KEY*> pubKeyCache;
    static mutex pubKeyCacheMutex;

    // Provide a single EC_GROUP for secp256k1 to avoid repeated creation/destruction.
    const EC_GROUP* get_secp256k1_group() {
        static const EC_GROUP* g = []() -> const EC_GROUP* {
            EC_GROUP* grp = EC_GROUP_new_by_curve_name(NID_secp256k1);
            // Keep grp alive for program lifetime; return as const pointer
            return grp;
        }();
        return g;
    }

    // Fast base64 decode/encode (compatible with standard base64 without newlines).
    // These functions are intentionally internal replacements for BIO-based versions.
    // They follow the standard RFC4648 alphabet and produce/consume '=' padding.
    static const string B64_CHARS =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    inline string fastBase64Encode(const vector<uint8_t>& data) {
        if (data.empty()) return "";
        string out;
        out.reserve(((data.size() + 2) / 3) * 4);
        int val = 0;
        int valb = -6;
        for (uint8_t c : data) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                out.push_back(B64_CHARS[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) out.push_back(B64_CHARS[((val << 8) >> (valb + 8)) & 0x3F]);
        while (out.size() % 4) out.push_back('=');
        return out;
    }

        inline vector<uint8_t> fastBase64Decode(const string& in) {
        static int Tstatic[256];
        static bool init = false;
        if (!init) {
            fill(begin(Tstatic), end(Tstatic), -1);
            for (int i = 0; i < (int)B64_CHARS.size(); ++i) Tstatic[(unsigned char)B64_CHARS[i]] = i;
            init = true;
        }

        int len = (int)in.size();
        if (len == 0) return {};
        vector<uint8_t> out;
        out.reserve((len * 3) / 4);
        int val = 0, valb = -8;
        for (unsigned char c : in) {
            int d = (int)Tstatic[c];
            if (d == -1) {
                if (c == '=') break;
                continue;
            }
            val = (val << 6) + d;
            valb += 6;
            if (valb >= 0) {
                out.push_back((uint8_t)((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return out;
    }

    // sha256 that returns raw bytes (internal helper)
    inline vector<uint8_t> sha256Bytes(const vector<uint8_t>& data) {
        vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        if (!data.empty()) SHA256_Update(&ctx, data.data(), data.size());
        SHA256_Final(hash.data(), &ctx);
        return hash;
    }

    // Create or retrieve EC_KEY* from cache given private key (base64 string).
    // Returns a pointer owned by cache (do not free).
    EC_KEY* get_cached_eckey_from_priv_base64(const string& privBase64) {
        lock_guard<mutex> lk(g_cache_mutex);
        auto it = g_eckey_cache.find(privBase64);
        if (it != g_eckey_cache.end()) return it->second;

        // decode base64 -> bytes
        vector<uint8_t> privBytes = fastBase64Decode(privBase64);
        if (privBytes.size() != 32) return nullptr;

        BIGNUM* privBN = BN_bin2bn(privBytes.data(), (int)privBytes.size(), nullptr);
        if (!privBN) {
            return nullptr;
        }

        EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (!ecKey) {
            BN_free(privBN);
            return nullptr;
        }

        if (EC_KEY_set_private_key(ecKey, privBN) != 1) {
            BN_free(privBN);
            EC_KEY_free(ecKey);
            return nullptr;
        }

        const EC_GROUP* group = get_secp256k1_group();
        // derive public point from private (point multiplication)
        EC_POINT* pubPoint = EC_POINT_new((EC_GROUP*)group);
        if (!pubPoint) {
            BN_free(privBN);
            EC_KEY_free(ecKey);
            return nullptr;
        }
        if (EC_POINT_mul((EC_GROUP*)group, pubPoint, privBN, nullptr, nullptr, nullptr) != 1) {
            EC_POINT_free(pubPoint);
            BN_free(privBN);
            EC_KEY_free(ecKey);
            return nullptr;
        }

        if (EC_KEY_set_public_key(ecKey, pubPoint) != 1) {
            EC_POINT_free(pubPoint);
            BN_free(privBN);
            EC_KEY_free(ecKey);
            return nullptr;
        }

        EC_POINT_free(pubPoint);
        BN_free(privBN);

        // Cache permanently for program lifetime (tests long-running)
        g_eckey_cache.emplace(privBase64, ecKey);
        return ecKey;
    }

} // namespace

// ---------------------------- Public API implementations ----------------------------

string CryptoUtils::sha256(const string& data) {
    // Keep the original behavior (hex string) for external API by delegating to sha256(vector).
    return sha256(vector<uint8_t>(data.begin(), data.end()));
}

string CryptoUtils::sha256(const vector<uint8_t>& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    if (!data.empty()) SHA256_Update(&sha256, data.data(), data.size());
    SHA256_Final(hash, &sha256);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) { ss << hex << setw(2) << setfill('0') << (int)hash[i]; }
    return ss.str();
}

// Generación de claves ECDSA (sin cambios lógicos)
bool CryptoUtils::generateKeyPair(string& privateKey, string& publicKey) {
    vector<uint8_t> privKey, pubKey;
    if (!generateKeyPair(privKey, pubKey)) { return false; }
    privateKey = base64Encode(privKey);
    publicKey = base64Encode(pubKey);
    return true;
}

bool CryptoUtils::generateKeyPair(vector<uint8_t>& privateKey, vector<uint8_t>& publicKey) {
    EC_KEY* ecKey = createECKey();
    if (!ecKey) return false;

    if (!generateKeyPair(ecKey)) {
        EC_KEY_free(ecKey);
        return false;
    }

    const BIGNUM* privKeyBN = EC_KEY_get0_private_key(ecKey);
    privateKey.resize(BN_num_bytes(privKeyBN));
    BN_bn2bin(privKeyBN, privateKey.data());

    const EC_POINT* pubKeyPoint = EC_KEY_get0_public_key(ecKey);
    const EC_GROUP* group = get_secp256k1_group();

    size_t pubKeyLen = EC_POINT_point2oct((EC_GROUP*)group, pubKeyPoint, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
    publicKey.resize(pubKeyLen);
    EC_POINT_point2oct((EC_GROUP*)group, pubKeyPoint, POINT_CONVERSION_UNCOMPRESSED, publicKey.data(), pubKeyLen, nullptr);

    // free original ecKey created by createECKey/generateKeyPair
    EC_KEY_free(ecKey);
    return true;
}

// Firma digital - public API kept intact
string CryptoUtils::signMessage(const string& privateKey, const string& message) {
    // Use fast decode and internal vector-based sign, then base64 encode result
    vector<uint8_t> privKey = fastBase64Decode(privateKey);
    vector<uint8_t> msg(message.begin(), message.end());
    vector<uint8_t> signature = signMessage(privKey, msg);
    return base64Encode(signature);
}

vector<uint8_t> CryptoUtils::signMessage(const vector<uint8_t>& privateKey, const vector<uint8_t>& message) {
    // Build privateKey base64 to use cache lookup (must match derivePublicKey cache key)
    string privBase64 = base64Encode(privateKey); // base64Encode still available (fast implementation below)
    EC_KEY* ecKey = get_cached_eckey_from_priv_base64(privBase64);
    if (!ecKey) return {};

    // Compute hash bytes directly (avoid hex encoding round-trip)
    vector<uint8_t> hash = sha256Bytes(message);

    vector<uint8_t> signature(ECDSA_size(ecKey));
    unsigned int sigLen = 0;
    if (ECDSA_sign(0, hash.data(), (int)hash.size(), signature.data(), &sigLen, ecKey) != 1) {
        return {};
    }
    signature.resize(sigLen);
    return signature;
}

// Verificación de firma - public API kept intact
bool CryptoUtils::verifySignature(const string& publicKey, const string& message, const string& signature) {
    vector<uint8_t> pubKey = base64Decode(publicKey);
    vector<uint8_t> msg(message.begin(), message.end());
    vector<uint8_t> sig = base64Decode(signature);
    return verifySignature(pubKey, msg, sig);
}

bool CryptoUtils::verifySignature(const vector<uint8_t>& publicKey, const vector<uint8_t>& message, const vector<uint8_t>& signature) {
    if (publicKey.empty() || signature.empty()) return false;

    // Cache lookup
    string cacheKey(reinterpret_cast<const char*>(publicKey.data()), publicKey.size());
    EC_KEY* ecKey = nullptr;

    {
        lock_guard<mutex> lock(pubKeyCacheMutex);
        auto it = pubKeyCache.find(cacheKey);
        if (it != pubKeyCache.end()) {
            ecKey = it->second;
        } else {
            // Rebuild EC_KEY from octets
            const EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
            if (!group) return false;

            ecKey = EC_KEY_new_by_curve_name(NID_secp256k1);
            if (!ecKey) {
                EC_GROUP_free((EC_GROUP*)group);
                return false;
            }

            EC_POINT* point = EC_POINT_new(group);
            if (!point) {
                EC_KEY_free(ecKey);
                EC_GROUP_free((EC_GROUP*)group);
                return false;
            }

            if (EC_POINT_oct2point(group, point, publicKey.data(),
                                   (size_t)publicKey.size(), nullptr) != 1) {
                EC_POINT_free(point);
                EC_KEY_free(ecKey);
                EC_GROUP_free((EC_GROUP*)group);
                return false;
            }

            if (EC_KEY_set_public_key(ecKey, point) != 1) {
                EC_POINT_free(point);
                EC_KEY_free(ecKey);
                EC_GROUP_free((EC_GROUP*)group);
                return false;
            }

            EC_POINT_free(point);
            EC_GROUP_free((EC_GROUP*)group);

            // Guardar en cache
            pubKeyCache[cacheKey] = ecKey;
        }
    }

    // Hash del mensaje
    vector<uint8_t> hash = sha256Bytes(message);

    // Verificar firma
    int ok = ECDSA_verify(0, hash.data(), (int)hash.size(),
                          signature.data(), (int)signature.size(), ecKey);

    return ok == 1;
}

// Conversiones Base64/Hex (kept API but replaced with faster implementations)
string CryptoUtils::base64Encode(const vector<uint8_t>& data) {
    return fastBase64Encode(data);
}

vector<uint8_t> CryptoUtils::base64Decode(const string& encoded) {
    return fastBase64Decode(encoded);
}

string CryptoUtils::hexEncode(const vector<uint8_t>& data) {
    stringstream ss;
    for (uint8_t byte : data) { ss << hex << setw(2) << setfill('0') << (int)byte; }
    return ss.str();
}

vector<uint8_t> CryptoUtils::hexDecode(const string& hex) {
    vector<uint8_t> result;
    result.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
        result.push_back(byte);
    }
    return result;
}

// derivePublicKey: cache result per privateKeyBase64 (same external behavior)
string CryptoUtils::derivePublicKey(const string& privateKeyBase64) {
    {
        lock_guard<mutex> lk(g_cache_mutex);
        auto it = g_pubkey_cache.find(privateKeyBase64);
        if (it != g_pubkey_cache.end()) return it->second;
    }

    // Build/reuse EC_KEY from cached or create new
    EC_KEY* ecKey = get_cached_eckey_from_priv_base64(privateKeyBase64);
    if (!ecKey) return "";

    // Extract public key bytes
    int pubKeyLen = i2o_ECPublicKey(ecKey, nullptr);
    if (pubKeyLen <= 0) return "";
    vector<uint8_t> pubKeyBytes(pubKeyLen);
    unsigned char* p = pubKeyBytes.data();
    if (i2o_ECPublicKey(ecKey, &p) != pubKeyLen) return "";

    string encoded = base64Encode(pubKeyBytes);
    {
        lock_guard<mutex> lk(g_cache_mutex);
        g_pubkey_cache.emplace(privateKeyBase64, encoded);
    }
    return encoded;
}

string CryptoUtils::getAddressFromPublicKey(const string& publicKey) {
    vector<uint8_t> pubKey = base64Decode(publicKey);
    return getAddressFromPublicKey(pubKey);
}

string CryptoUtils::getAddressFromPublicKey(const vector<uint8_t>& publicKey) {
    if (publicKey.size() < 64) return "";

    // Remove prefix (first byte) if present; follow original behavior (publicKey.begin()+1)
    vector<uint8_t> pubKeyData(publicKey.begin() + 1, publicKey.end());
    vector<uint8_t> sha256Hash = sha256Bytes(pubKeyData);

    unsigned char ripemd160Hash[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160_CTX ripemd160;
    RIPEMD160_Init(&ripemd160);
    RIPEMD160_Update(&ripemd160, sha256Hash.data(), sha256Hash.size());
    RIPEMD160_Final(ripemd160Hash, &ripemd160);

    stringstream ss;
    for (int i = 0; i < 20; i++) { ss << hex << setw(2) << setfill('0') << (int)ripemd160Hash[i]; }
    return ss.str();
}

// publicKeyToAddress with caching (preserves original output)
string CryptoUtils::publicKeyToAddress(const string& publicKeyBase64) {
    {
        lock_guard<mutex> lk(g_cache_mutex);
        auto it = g_addr_cache.find(publicKeyBase64);
        if (it != g_addr_cache.end()) return it->second;
    }

    vector<uint8_t> pubKeyBytes = base64Decode(publicKeyBase64);
    if (pubKeyBytes.empty()) return "";

    unsigned char sha256Hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, pubKeyBytes.data(), pubKeyBytes.size());
    SHA256_Final(sha256Hash, &sha256);

    unsigned char ripemdHash[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160_CTX ripemd;
    RIPEMD160_Init(&ripemd);
    RIPEMD160_Update(&ripemd, sha256Hash, SHA256_DIGEST_LENGTH);
    RIPEMD160_Final(ripemdHash, &ripemd);

    stringstream ss;
    for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)ripemdHash[i];
    }
    string addr = ss.str();

    {
        lock_guard<mutex> lk(g_cache_mutex);
        g_addr_cache.emplace(publicKeyBase64, addr);
    }
    return addr;
}

bool CryptoUtils::isValidAddress(const string& addr) {
    if (addr.empty()) return false;
    if (addr.size() < 16) return false;
    return all_of(addr.begin(), addr.end(), [](unsigned char c) {
        return isalnum(c);
    });
}

// Validación de clave privada: mantiene la misma lógica pero reuse createECKey() group
bool CryptoUtils::isValidPrivateKey(const string& privateKey) {
    try {
        vector<uint8_t> privateKeyBytes = base64Decode(privateKey);
        if (privateKeyBytes.size() != 32) return false;

        BIGNUM* privKeyBN = BN_bin2bn(privateKeyBytes.data(), privateKeyBytes.size(), nullptr);
        if (!privKeyBN) return false;

        EC_KEY* ecKey = createECKey();
        if (!ecKey) {
            BN_free(privKeyBN);
            return false;
        }

        const EC_GROUP* group = EC_KEY_get0_group(ecKey);
        BIGNUM* order = BN_new();
        EC_GROUP_get_order((EC_GROUP*)group, order, nullptr);

        bool isValid = BN_is_zero(privKeyBN) == 0 && BN_cmp(privKeyBN, order) < 0;

        BN_free(privKeyBN);
        BN_free(order);
        EC_KEY_free(ecKey);
        return isValid;
    } catch (...) {
        return false;
    }
}

bool CryptoUtils::isValidPublicKey(const string& publicKey) {
    try {
        vector<uint8_t> publicKeyBytes = base64Decode(publicKey);
        if (publicKeyBytes.size() != 65) return false;
        if (publicKeyBytes[0] != 0x04) return false;

        EC_KEY* ecKey = createECKey();
        if (!ecKey) return false;

        const EC_GROUP* group = get_secp256k1_group();
        EC_POINT* point = EC_POINT_new((EC_GROUP*)group);
        int res = EC_POINT_oct2point((EC_GROUP*)group, point, publicKeyBytes.data(), publicKeyBytes.size(), nullptr);
        bool isValid = (res == 1) && (EC_POINT_is_on_curve((EC_GROUP*)group, point, nullptr) == 1);

        EC_POINT_free(point);
        EC_KEY_free(ecKey);
        return isValid;
    } catch (...) {
        return false;
    }
}

// Helper functions (createECKey kept for compatibility)
EC_KEY* CryptoUtils::createECKey() {
    EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    return ecKey;
}

bool CryptoUtils::generateKeyPair(EC_KEY* ecKey) {
    if (!ecKey) return false;
    return EC_KEY_generate_key(ecKey) == 1;
}

void CryptoUtils::clearCaches() {
    lock_guard<mutex> lock(g_cache_mutex);
    g_pubkey_cache.clear();
    g_addr_cache.clear();

    for (auto& kv : g_eckey_cache) {
        EC_KEY_free(kv.second);
    }
    g_eckey_cache.clear();

    lock_guard<mutex> lock2(pubKeyCacheMutex);
    for (auto& kv : pubKeyCache) {
        EC_KEY_free(kv.second);
    }
    pubKeyCache.clear();
}
