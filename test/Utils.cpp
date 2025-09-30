#include "Utils.hpp"

// ============================================================================
// ---------------------------- Internal Helpers & Caches ---------------------
// ============================================================================
namespace {

    // ---- Constants ----
    static constexpr int PRIVATE_KEY_SIZE = 32;
    static constexpr int PUBLIC_KEY_UNCOMPRESSED_SIZE = 65;
    static constexpr int SHA256_SIZE = SHA256_DIGEST_LENGTH;
    static constexpr int RIPEMD160_SIZE = RIPEMD160_DIGEST_LENGTH;
    static constexpr time_t CACHE_EXPIRY_SECONDS = 3600; // 1 hora
    static constexpr time_t CLEANUP_INTERVAL_SECONDS = 300; // 5 minutos
    
    static const string B64_CHARS = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // ---- Enhanced Cache Structures ----
    struct CachedKeyPair {
        EC_KEY* ecKey;
        vector<uint8_t> publicKeyBytes;
        string publicKeyBase64;
        time_t lastUsed;
        size_t signatureSize; // Pre-calculated
    };

    // ---- Mutex & Enhanced Global Caches ----
    static mutex g_cache_mutex;
    static mutex pubKeyCacheMutex;

    static unordered_map<string, CachedKeyPair> g_keypair_cache;  // privateKeyBase64 -> CachedKeyPair
    static unordered_map<string, string> g_addr_cache;            // publicKeyBase64 -> address hex
    static unordered_map<string, EC_KEY*> pubKeyCache;            // publicKeyRaw -> EC_KEY*

    // ---- ECDSA Signature Pool ----
    class ECDSASignaturePool {
    private:
        mutex poolMutex;
        vector<ECDSA_SIG*> availableSigs;
        int maxPoolSize;
        
    public:
        ECDSASignaturePool(int maxSize = 100) : maxPoolSize(maxSize) {}
        
        ~ECDSASignaturePool() {
            clear();
        }
        
        ECDSA_SIG* acquire() {
            lock_guard<mutex> lock(poolMutex);
            if (!availableSigs.empty()) {
                ECDSA_SIG* sig = availableSigs.back();
                availableSigs.pop_back();
                return sig;
            }
            return ECDSA_SIG_new();
        }
        
        void release(ECDSA_SIG* sig) {
            if (!sig) return;
            
            // Reset the signature for reuse
            const BIGNUM* r = ECDSA_SIG_get0_r(sig);
            const BIGNUM* s = ECDSA_SIG_get0_s(sig);
            if (r) BN_clear(const_cast<BIGNUM*>(r));
            if (s) BN_clear(const_cast<BIGNUM*>(s));
            
            lock_guard<mutex> lock(poolMutex);
            if (availableSigs.size() < maxPoolSize) {
                availableSigs.push_back(sig);
            } else {
                ECDSA_SIG_free(sig);
            }
        }
        
        void clear() {
            lock_guard<mutex> lock(poolMutex);
            for (auto sig : availableSigs) {
                ECDSA_SIG_free(sig);
            }
            availableSigs.clear();
        }
    };

    static ECDSASignaturePool g_ecdsa_pool;

    // ---- Memory Management Helpers ----
    struct BIGNUMPtr {
        BIGNUM* ptr;
        BIGNUMPtr(BIGNUM* p = nullptr) : ptr(p) {}
        ~BIGNUMPtr() { if (ptr) BN_free(ptr); }
        BIGNUM* get() const { return ptr; }
        BIGNUM* release() { BIGNUM* p = ptr; ptr = nullptr; return p; }
    };

    struct EC_KEYPtr {
        EC_KEY* ptr;
        EC_KEYPtr(EC_KEY* p = nullptr) : ptr(p) {}
        ~EC_KEYPtr() { if (ptr) EC_KEY_free(ptr); }
        EC_KEY* get() const { return ptr; }
        EC_KEY* release() { EC_KEY* p = ptr; ptr = nullptr; return p; }
    };

    struct EC_POINTPtr {
        EC_POINT* ptr;
        EC_POINTPtr(EC_POINT* p = nullptr) : ptr(p) {}
        ~EC_POINTPtr() { if (ptr) EC_POINT_free(ptr); }
        EC_POINT* get() const { return ptr; }
    };

    struct EC_GROUPPtr {
        EC_GROUP* ptr;
        EC_GROUPPtr(EC_GROUP* p = nullptr) : ptr(p) {}
        ~EC_GROUPPtr() { if (ptr) EC_GROUP_free(ptr); }
        EC_GROUP* get() const { return ptr; }
    };

    // ---- EC_GROUP for secp256k1 ----
    const EC_GROUP* get_secp256k1_group() {
        static const EC_GROUP* group = []() -> const EC_GROUP* {
            return EC_GROUP_new_by_curve_name(NID_secp256k1);
        }();
        return group;
    }

    // ---- Base64 Encoding/Decoding ----
    string fastBase64Encode(const vector<uint8_t>& data) {
        if (data.empty()) return "";

        string result;
        result.reserve(((data.size() + 2) / 3) * 4);

        int value = 0;
        int bits = -6;
        
        for (uint8_t byte : data) {
            value = (value << 8) + byte;
            bits += 8;
            while (bits >= 0) {
                result.push_back(B64_CHARS[(value >> bits) & 0x3F]);
                bits -= 6;
            }
        }

        if (bits > -6) {
            result.push_back(B64_CHARS[((value << 8) >> (bits + 8)) & 0x3F]);
        }

        while (result.size() % 4) {
            result.push_back('=');
        }

        return result;
    }

    vector<uint8_t> fastBase64Decode(const string& encoded) {
        static vector<int> decode_table(256, -1);
        static bool initialized = false;

        if (!initialized) {
            for (size_t i = 0; i < B64_CHARS.size(); ++i) {
                decode_table[(unsigned char)B64_CHARS[i]] = i;
            }
            initialized = true;
        }

        if (encoded.empty()) return {};

        vector<uint8_t> result;
        result.reserve((encoded.size() * 3) / 4);

        int value = 0;
        int bits = -8;
        
        for (unsigned char c : encoded) {
            if (c == '=') break;
            
            int digit = decode_table[c];
            if (digit == -1) continue;

            value = (value << 6) + digit;
            bits += 6;
            
            if (bits >= 0) {
                result.push_back(static_cast<uint8_t>((value >> bits) & 0xFF));
                bits -= 8;
            }
        }

        return result;
    }

    // ---- Hashing Functions ----
    vector<uint8_t> sha256Bytes(const vector<uint8_t>& data) {
        vector<uint8_t> hash(SHA256_SIZE);
        SHA256_CTX context;
        
        SHA256_Init(&context);
        if (!data.empty()) {
            SHA256_Update(&context, data.data(), data.size());
        }
        SHA256_Final(hash.data(), &context);
        
        return hash;
    }

    vector<uint8_t> ripemd160Bytes(const vector<uint8_t>& data) {
        vector<uint8_t> hash(RIPEMD160_SIZE);
        RIPEMD160_CTX context;
        
        RIPEMD160_Init(&context);
        RIPEMD160_Update(&context, data.data(), data.size());
        RIPEMD160_Final(hash.data(), &context);
        
        return hash;
    }

    // ---- Enhanced Key Conversion Helpers ----
    vector<uint8_t> derivePublicKeyBytes(EC_KEY* ecKey) {
        if (!ecKey) return {};
        
        const EC_POINT* publicPoint = EC_KEY_get0_public_key(ecKey);
        const EC_GROUP* group = get_secp256k1_group();
        
        size_t publicKeyLength = EC_POINT_point2oct(
            group, publicPoint, POINT_CONVERSION_UNCOMPRESSED, 
            nullptr, 0, nullptr
        );
        
        if (publicKeyLength == 0) return {};
        
        vector<uint8_t> publicKeyBytes(publicKeyLength);
        EC_POINT_point2oct(
            group, publicPoint, POINT_CONVERSION_UNCOMPRESSED,
            publicKeyBytes.data(), publicKeyLength, nullptr
        );
        
        return publicKeyBytes;
    }

    EC_KEY* createECKeyFromPrivateBytes(const vector<uint8_t>& privateBytes) {
        if (privateBytes.size() != PRIVATE_KEY_SIZE) return nullptr;

        BIGNUMPtr privateBN(BN_bin2bn(privateBytes.data(), privateBytes.size(), nullptr));
        if (!privateBN.get()) return nullptr;

        EC_KEYPtr ecKey(EC_KEY_new_by_curve_name(NID_secp256k1));
        if (!ecKey.get()) return nullptr;

        if (EC_KEY_set_private_key(ecKey.get(), privateBN.get()) != 1) {
            return nullptr;
        }

        const EC_GROUP* group = get_secp256k1_group();
        EC_POINTPtr publicPoint(EC_POINT_new(group));
        if (!publicPoint.get()) return nullptr;

        if (EC_POINT_mul(group, publicPoint.get(), privateBN.get(), nullptr, nullptr, nullptr) != 1) {
            return nullptr;
        }

        if (EC_KEY_set_public_key(ecKey.get(), publicPoint.get()) != 1) {
            return nullptr;
        }

        return ecKey.release();
    }

    // ---- Enhanced Cache Management ----
    void cleanupExpiredCache() {
        static time_t lastCleanup = 0;
        time_t now = time(nullptr);
        
        if (now - lastCleanup < CLEANUP_INTERVAL_SECONDS) return;

        vector<string> keysToRemove;
        for (const auto& [key, keyPair] : g_keypair_cache) {
            if (now - keyPair.lastUsed > CACHE_EXPIRY_SECONDS) {
                keysToRemove.push_back(key);
            }
        }
        
        for (const auto& key : keysToRemove) {
            if (g_keypair_cache[key].ecKey) {
                EC_KEY_free(g_keypair_cache[key].ecKey);
            }
            g_keypair_cache.erase(key);
        }
        
        lastCleanup = now;
        
        if (!keysToRemove.empty()) {
            cout << "Limpieza automática: " << keysToRemove.size() 
                      << " entradas expiradas removidas\n";
        }
    }

    EC_KEY* getOptimizedCachedECKey(const string& privateKeyBase64) {
        lock_guard<mutex> lock(g_cache_mutex);
        
        // Buscar en caché primero
        auto it = g_keypair_cache.find(privateKeyBase64);
        if (it != g_keypair_cache.end()) {
            it->second.lastUsed = time(nullptr);
            return it->second.ecKey;
        }

        // Si no está en caché, crear nueva entrada
        vector<uint8_t> privateBytes = fastBase64Decode(privateKeyBase64);
        if (privateBytes.size() != PRIVATE_KEY_SIZE) return nullptr;

        EC_KEY* ecKey = createECKeyFromPrivateBytes(privateBytes);
        if (!ecKey) return nullptr;

        // Pre-calcular todos los datos que podrían necesitarse
        vector<uint8_t> publicKeyBytes = derivePublicKeyBytes(ecKey);
        string publicKeyBase64 = fastBase64Encode(publicKeyBytes);
        size_t signatureSize = ECDSA_size(ecKey);

        // Almacenar en caché
        g_keypair_cache[privateKeyBase64] = {
            ecKey, 
            publicKeyBytes, 
            publicKeyBase64, 
            time(nullptr),
            signatureSize
        };

        // Ejecutar limpieza periódica
        cleanupExpiredCache();
        
        return ecKey;
    }

    // ---- Optimized Signing with Pool ----
    vector<uint8_t> signMessageOptimized(EC_KEY* ecKey, const vector<uint8_t>& message) {
        if (!ecKey) return {};

        vector<uint8_t> hash = sha256Bytes(message);
        
        // Usar el pool de firmas ECDSA
        ECDSA_SIG* signature = g_ecdsa_pool.acquire();
        if (!signature) return {};

        // Realizar la firma
        signature = ECDSA_do_sign(hash.data(), hash.size(), ecKey);
        if (!signature) {
            g_ecdsa_pool.release(signature);
            return {};
        }

        // Convertir signature a formato DER
        int derLength = i2d_ECDSA_SIG(signature, nullptr);
        if (derLength <= 0) {
            g_ecdsa_pool.release(signature);
            return {};
        }

        vector<uint8_t> derSignature(derLength);
        unsigned char* derData = derSignature.data();
        i2d_ECDSA_SIG(signature, &derData);

        // Devolver signature al pool para reuso
        g_ecdsa_pool.release(signature);

        return derSignature;
    }

} // namespace

// ============================================================================
// ---------------------------- Public API Implementations --------------------
// ============================================================================

// ---- Hashing ----
string CryptoUtils::sha256(const string& data) {
    return sha256(vector<uint8_t>(data.begin(), data.end()));
}

string CryptoUtils::sha256(const vector<uint8_t>& data) {
    unsigned char hash[SHA256_SIZE];
    SHA256_CTX context;
    
    SHA256_Init(&context);
    if (!data.empty()) {
        SHA256_Update(&context, data.data(), data.size());
    }
    SHA256_Final(hash, &context);

    stringstream hexStream;
    for (int i = 0; i < SHA256_SIZE; i++) {
        hexStream << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
    }
    
    return hexStream.str();
}

// ---- Key Generation ----
bool CryptoUtils::generateKeyPair(string& privateKey, string& publicKey) {
    vector<uint8_t> privateKeyBytes, publicKeyBytes;
    
    if (!generateKeyPair(privateKeyBytes, publicKeyBytes)) {
        return false;
    }

    privateKey = base64Encode(privateKeyBytes);
    publicKey = base64Encode(publicKeyBytes);
    
    return true;
}

bool CryptoUtils::generateKeyPair(vector<uint8_t>& privateKey, vector<uint8_t>& publicKey) {
    EC_KEYPtr ecKey(createECKey());
    if (!ecKey.get()) return false;

    if (!generateKeyPair(ecKey.get())) {
        return false;
    }

    // Extract private key
    const BIGNUM* privateBN = EC_KEY_get0_private_key(ecKey.get());
    privateKey.resize(BN_num_bytes(privateBN));
    BN_bn2bin(privateBN, privateKey.data());

    // Extract public key
    const EC_POINT* publicPoint = EC_KEY_get0_public_key(ecKey.get());
    const EC_GROUP* group = get_secp256k1_group();

    size_t publicKeyLength = EC_POINT_point2oct(
        group, publicPoint, POINT_CONVERSION_UNCOMPRESSED, 
        nullptr, 0, nullptr
    );
    
    publicKey.resize(publicKeyLength);
    EC_POINT_point2oct(
        group, publicPoint, POINT_CONVERSION_UNCOMPRESSED,
        publicKey.data(), publicKeyLength, nullptr
    );

    return true;
}

// ---- Optimized Signing ----
string CryptoUtils::signMessage(const string& privateKey, const string& message) {
    vector<uint8_t> privateKeyBytes = fastBase64Decode(privateKey);
    vector<uint8_t> messageBytes(message.begin(), message.end());
    vector<uint8_t> signature = signMessage(privateKeyBytes, messageBytes);
    
    return base64Encode(signature);
}

vector<uint8_t> CryptoUtils::signMessage(const vector<uint8_t>& privateKey,
                                         const vector<uint8_t>& message) {
    string privateKeyBase64 = base64Encode(privateKey);
    
    // Usar la caché optimizada
    EC_KEY* ecKey = getOptimizedCachedECKey(privateKeyBase64);
    if (!ecKey) return {};

    // Usar el método de firma optimizado con pool
    return signMessageOptimized(ecKey, message);
}

// ---- Verification ----
bool CryptoUtils::verifySignature(const string& publicKey,
                                  const string& message,
                                  const string& signature) {
    vector<uint8_t> publicKeyBytes = base64Decode(publicKey);
    vector<uint8_t> messageBytes(message.begin(), message.end());
    vector<uint8_t> signatureBytes = base64Decode(signature);
    
    return verifySignature(publicKeyBytes, messageBytes, signatureBytes);
}

bool CryptoUtils::verifySignature(const vector<uint8_t>& publicKey,
                                  const vector<uint8_t>& message,
                                  const vector<uint8_t>& signature) {
    if (publicKey.empty() || signature.empty()) return false;

    EC_KEY* ecKey = getCachedPublicKey(publicKey);
    if (!ecKey) return false;

    vector<uint8_t> hash = sha256Bytes(message);
    int result = ECDSA_verify(0, hash.data(), hash.size(),
                             signature.data(), signature.size(), ecKey);

    return result == 1;
}

// ---- Base64/Hex Encoding ----
string CryptoUtils::base64Encode(const vector<uint8_t>& data) {
    return fastBase64Encode(data);
}

vector<uint8_t> CryptoUtils::base64Decode(const string& encoded) {
    return fastBase64Decode(encoded);
}

string CryptoUtils::hexEncode(const vector<uint8_t>& data) {
    stringstream hexStream;
    for (uint8_t byte : data) {
        hexStream << hex << setw(2) << setfill('0') << static_cast<int>(byte);
    }
    return hexStream.str();
}

vector<uint8_t> CryptoUtils::hexDecode(const string& hex) {
    vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);

    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    
    return bytes;
}

// ---- Public Key Derivation ----
string CryptoUtils::derivePublicKey(const string& privateKeyBase64) {
    {
        lock_guard<mutex> lock(g_cache_mutex);
        auto it = g_keypair_cache.find(privateKeyBase64);
        if (it != g_keypair_cache.end()) {
            return it->second.publicKeyBase64;
        }
    }

    EC_KEY* ecKey = getOptimizedCachedECKey(privateKeyBase64);
    if (!ecKey) return "";

    // La clave pública ya está pre-calculada en la caché
    lock_guard<mutex> lock(g_cache_mutex);
    auto it = g_keypair_cache.find(privateKeyBase64);
    if (it != g_keypair_cache.end()) {
        return it->second.publicKeyBase64;
    }

    return "";
}

// ---- Address Generation ----
string CryptoUtils::getAddressFromPublicKey(const string& publicKey) {
    vector<uint8_t> publicKeyBytes = base64Decode(publicKey);
    return getAddressFromPublicKey(publicKeyBytes);
}

string CryptoUtils::getAddressFromPublicKey(const vector<uint8_t>& publicKey) {
    if (publicKey.size() < 64) return "";

    // Skip the compression byte (0x04) for uncompressed keys
    vector<uint8_t> publicKeyData(publicKey.begin() + 1, publicKey.end());
    vector<uint8_t> sha256Hash = sha256Bytes(publicKeyData);
    vector<uint8_t> ripemd160Hash = ripemd160Bytes(sha256Hash);

    return hexEncode(ripemd160Hash);
}

string CryptoUtils::publicKeyToAddress(const string& publicKeyBase64) {
    {
        lock_guard<mutex> lock(g_cache_mutex);
        auto it = g_addr_cache.find(publicKeyBase64);
        if (it != g_addr_cache.end()) {
            return it->second;
        }
    }

    vector<uint8_t> publicKeyBytes = base64Decode(publicKeyBase64);
    if (publicKeyBytes.empty()) return "";

    vector<uint8_t> sha256Hash = sha256Bytes(publicKeyBytes);
    vector<uint8_t> ripemd160Hash = ripemd160Bytes(sha256Hash);
    
    string address = hexEncode(ripemd160Hash);
    
    {
        lock_guard<mutex> lock(g_cache_mutex);
        g_addr_cache.emplace(publicKeyBase64, address);
    }
    
    return address;
}

// ---- Validation ----
bool CryptoUtils::isValidAddress(const string& address) {
    if (address.empty() || address.size() < 16) return false;
    
    return all_of(address.begin(), address.end(), [](unsigned char c) {
        return isalnum(c);
    });
}

bool CryptoUtils::isValidPrivateKey(const string& privateKey) {
    try {
        vector<uint8_t> privateKeyBytes = base64Decode(privateKey);
        if (privateKeyBytes.size() != PRIVATE_KEY_SIZE) return false;

        BIGNUMPtr privateBN(BN_bin2bn(privateKeyBytes.data(), privateKeyBytes.size(), nullptr));
        if (!privateBN.get()) return false;

        EC_KEYPtr ecKey(createECKey());
        if (!ecKey.get()) return false;

        const EC_GROUP* group = EC_KEY_get0_group(ecKey.get());
        BIGNUMPtr order(BN_new());
        EC_GROUP_get_order(group, order.get(), nullptr);

        bool isValid = BN_is_zero(privateBN.get()) == 0 && 
                      BN_cmp(privateBN.get(), order.get()) < 0;

        return isValid;
    } catch (...) {
        return false;
    }
}

bool CryptoUtils::isValidPublicKey(const string& publicKey) {
    try {
        vector<uint8_t> publicKeyBytes = base64Decode(publicKey);
        if (publicKeyBytes.size() != PUBLIC_KEY_UNCOMPRESSED_SIZE) return false;
        if (publicKeyBytes[0] != 0x04) return false;

        EC_KEYPtr ecKey(createECKey());
        if (!ecKey.get()) return false;

        const EC_GROUP* group = get_secp256k1_group();
        EC_POINTPtr point(EC_POINT_new(group));

        int result = EC_POINT_oct2point(group, point.get(),
                                       publicKeyBytes.data(),
                                       publicKeyBytes.size(), nullptr);

        bool isValid = (result == 1) &&
                      (EC_POINT_is_on_curve(group, point.get(), nullptr) == 1);

        return isValid;
    } catch (...) {
        return false;
    }
}

// ---- Helper Methods ----
EC_KEY* CryptoUtils::createECKey() {
    return EC_KEY_new_by_curve_name(NID_secp256k1);
}

bool CryptoUtils::generateKeyPair(EC_KEY* ecKey) {
    return ecKey && EC_KEY_generate_key(ecKey) == 1;
}

void CryptoUtils::clearCaches() {
    int keysFreed = 0;
    int pubKeysFreed = 0;
    
    // Limpiar cachés principales
    {
        lock_guard<mutex> lock(g_cache_mutex);
        
        // Limpiar caché de keypairs
        keysFreed = g_keypair_cache.size();
        for (auto& [key, keyPair] : g_keypair_cache) {
            if (keyPair.ecKey) {
                EC_KEY_free(keyPair.ecKey);
            }
        }
        g_keypair_cache.clear();
        
        // Limpiar caché de direcciones
        g_addr_cache.clear();
    }
    
    // Limpiar caché de claves públicas
    {
        lock_guard<mutex> lock(pubKeyCacheMutex);
        pubKeysFreed = pubKeyCache.size();
        for (auto& [key, ecKey] : pubKeyCache) {
            if (ecKey) {
                EC_KEY_free(ecKey);
            }
        }
        pubKeyCache.clear();
    }
    
    // Limpiar pool de firmas
    g_ecdsa_pool.clear();
    
    // Forzar limpieza inmediata resetando el temporizador
    cleanupExpiredCache();
    
    cout << "Cachés limpiadas: " << keysFreed << " keypairs, " 
              << pubKeysFreed << " claves públicas liberadas\n";
}

// ---- Private Helper Methods ----
EC_KEY* CryptoUtils::getCachedPublicKey(const vector<uint8_t>& publicKey) {
    string cacheKey(reinterpret_cast<const char*>(publicKey.data()), publicKey.size());
    
    lock_guard<mutex> lock(pubKeyCacheMutex);
    
    auto it = pubKeyCache.find(cacheKey);
    if (it != pubKeyCache.end()) {
        return it->second;
    }

    EC_GROUPPtr group(EC_GROUP_new_by_curve_name(NID_secp256k1));
    if (!group.get()) return nullptr;

    EC_KEYPtr ecKey(EC_KEY_new_by_curve_name(NID_secp256k1));
    if (!ecKey.get()) return nullptr;

    EC_POINTPtr point(EC_POINT_new(group.get()));
    if (!point.get()) return nullptr;

    if (EC_POINT_oct2point(group.get(), point.get(),
                          publicKey.data(), publicKey.size(), nullptr) != 1) {
        return nullptr;
    }

    if (EC_KEY_set_public_key(ecKey.get(), point.get()) != 1) {
        return nullptr;
    }

    EC_KEY* result = ecKey.release();
    pubKeyCache[cacheKey] = result;
    
    return result;
}
