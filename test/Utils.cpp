#include "Utils.hpp"
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <algorithm>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

// Hashing SHA-256
string CryptoUtils::sha256(const string& data) { return sha256(vector<uint8_t>(data.begin(), data.end())); }

string CryptoUtils::sha256(const vector<uint8_t>& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.data(), data.size());
    SHA256_Final(hash, &sha256);
    
    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) { ss << hex << setw(2) << setfill('0') << (int)hash[i]; }
    
    return ss.str();
}

// Generación de claves ECDSA
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
    
    // Obtener private key
    const BIGNUM* privKeyBN = EC_KEY_get0_private_key(ecKey);
    privateKey.resize(BN_num_bytes(privKeyBN));
    BN_bn2bin(privKeyBN, privateKey.data());
    
    // Obtener public key
    const EC_POINT* pubKeyPoint = EC_KEY_get0_public_key(ecKey);
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    
    size_t pubKeyLen = EC_POINT_point2oct(group, pubKeyPoint, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
    publicKey.resize(pubKeyLen);
    EC_POINT_point2oct(group, pubKeyPoint, POINT_CONVERSION_UNCOMPRESSED, publicKey.data(), pubKeyLen, nullptr);
    
    EC_GROUP_free(group);
    EC_KEY_free(ecKey);
    return true;
}

// Firma digital
string CryptoUtils::signMessage(const string& privateKey, const string& message) {
    vector<uint8_t> privKey = base64Decode(privateKey);
    vector<uint8_t> msg(message.begin(), message.end());
    vector<uint8_t> signature = signMessage(privKey, msg);
    
    return base64Encode(signature);
}

vector<uint8_t> CryptoUtils::signMessage(const vector<uint8_t>& privateKey, const vector<uint8_t>& message) {
    EC_KEY* ecKey = createECKey();
    if (!ecKey) return {};
    
    // Configurar private key
    BIGNUM* privKeyBN = BN_bin2bn(privateKey.data(), privateKey.size(), nullptr);
    if (!EC_KEY_set_private_key(ecKey, privKeyBN)) {
        BN_free(privKeyBN);
        EC_KEY_free(ecKey);
        return {};
    }
    
    // Generar public key correspondiente
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_POINT* pubKeyPoint = EC_POINT_new(group);
    EC_POINT_mul(group, pubKeyPoint, privKeyBN, nullptr, nullptr, nullptr);
    EC_KEY_set_public_key(ecKey, pubKeyPoint);
    
    BN_free(privKeyBN);
    EC_POINT_free(pubKeyPoint);
    EC_GROUP_free(group);
    
    // Firmar el mensaje
    vector<uint8_t> signature(ECDSA_size(ecKey));
    unsigned int sigLen;
    
    vector<uint8_t> hash = hexDecode(sha256(message));
    
    if (ECDSA_sign(0, hash.data(), hash.size(), signature.data(), &sigLen, ecKey) != 1) {
        EC_KEY_free(ecKey);
        return {};
    }
    
    signature.resize(sigLen);
    EC_KEY_free(ecKey);
    return signature;
}

// Verificación de firma
bool CryptoUtils::verifySignature(const string& publicKey, const string& message, const string& signature) {
    vector<uint8_t> pubKey = base64Decode(publicKey);
    vector<uint8_t> msg(message.begin(), message.end());
    vector<uint8_t> sig = base64Decode(signature);
    
    return verifySignature(pubKey, msg, sig);
}

bool CryptoUtils::verifySignature(const vector<uint8_t>& publicKey, const vector<uint8_t>& message, const vector<uint8_t>& signature) {
    EC_KEY* ecKey = createECKey();
    if (!ecKey) return false;
    
    // Configurar public key
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_POINT* pubKeyPoint = EC_POINT_new(group);
    
    if (!EC_POINT_oct2point(group, pubKeyPoint, publicKey.data(), publicKey.size(), nullptr) || !EC_KEY_set_public_key(ecKey, pubKeyPoint)) {
        EC_POINT_free(pubKeyPoint);
        EC_GROUP_free(group);
        EC_KEY_free(ecKey);
        return false;
    }
    
    vector<uint8_t> hash = hexDecode(sha256(message));
    
    int result = ECDSA_verify(0, hash.data(), hash.size(), signature.data(), signature.size(), ecKey);
    
    EC_POINT_free(pubKeyPoint);
    EC_GROUP_free(group);
    EC_KEY_free(ecKey);
    
    return result == 1;
}

// Conversiones
string CryptoUtils::base64Encode(const vector<uint8_t>& data) {
    BIO* bio = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    bio = BIO_push(bio, bmem);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);
    
    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio, &bptr);
    
    string result(bptr->data, bptr->length);
    
    BIO_free_all(bio);
    return result;
}

vector<uint8_t> CryptoUtils::base64Decode(const string& encoded) {
    BIO* bio = BIO_new_mem_buf(encoded.data(), encoded.size());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
    vector<uint8_t> result(encoded.size());
    int length = BIO_read(bio, result.data(), encoded.size());
    result.resize(length);
    
    BIO_free_all(bio);
    return result;
}

string CryptoUtils::hexEncode(const vector<uint8_t>& data) {
    stringstream ss;
    for (uint8_t byte : data) { ss << hex << setw(2) << setfill('0') << (int)byte; }
    return ss.str();
}

vector<uint8_t> CryptoUtils::hexDecode(const string& hex) {
    vector<uint8_t> result;
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
        result.push_back(byte);
    }
    
    return result;
}

// Dirección desde clave pública
string CryptoUtils::derivePublicKey(const string& privateKeyBase64) {
    // 1️⃣ Decodificar private key de Base64
    vector<uint8_t> privKeyBytes = base64Decode(privateKeyBase64);
    if (privKeyBytes.size() != 32) return "";

    // 2️⃣ Crear BIGNUM desde bytes
    BIGNUM* privBN = BN_bin2bn(privKeyBytes.data(), privKeyBytes.size(), nullptr);
    if (!privBN) return "";

    // 3️⃣ Crear EC_KEY en secp256k1
    EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ecKey) {
        BN_free(privBN);
        return "";
    }

    if (!EC_KEY_set_private_key(ecKey, privBN)) {
        BN_free(privBN);
        EC_KEY_free(ecKey);
        return "";
    }

    // 4️⃣ Derivar la clave pública a partir de la privada
    const EC_GROUP* group = EC_KEY_get0_group(ecKey);
    EC_POINT* pubKeyPoint = EC_POINT_new(group);
    if (!EC_POINT_mul(group, pubKeyPoint, privBN, nullptr, nullptr, nullptr)) {
        BN_free(privBN);
        EC_POINT_free(pubKeyPoint);
        EC_KEY_free(ecKey);
        return "";
    }

    if (!EC_KEY_set_public_key(ecKey, pubKeyPoint)) {
        BN_free(privBN);
        EC_POINT_free(pubKeyPoint);
        EC_KEY_free(ecKey);
        return "";
    }

    // 5️⃣ Convertir EC_POINT a bytes (formato comprimido o no comprimido)
    int pubKeyLen = i2o_ECPublicKey(ecKey, nullptr); // obtener longitud
    if (pubKeyLen == 0) {
        BN_free(privBN);
        EC_POINT_free(pubKeyPoint);
        EC_KEY_free(ecKey);
        return "";
    }

    vector<uint8_t> pubKeyBytes(pubKeyLen);
    unsigned char* p = pubKeyBytes.data();
    if (i2o_ECPublicKey(ecKey, &p) != pubKeyLen) {
        BN_free(privBN);
        EC_POINT_free(pubKeyPoint);
        EC_KEY_free(ecKey);
        return "";
    }

    // 6️⃣ Limpiar memoria
    BN_free(privBN);
    EC_POINT_free(pubKeyPoint);
    EC_KEY_free(ecKey);

    // 7️⃣ Codificar en Base64 y devolver
    return base64Encode(pubKeyBytes);
}

string CryptoUtils::getAddressFromPublicKey(const string& publicKey) {
    vector<uint8_t> pubKey = base64Decode(publicKey);
    return getAddressFromPublicKey(pubKey);
}

string CryptoUtils::getAddressFromPublicKey(const vector<uint8_t>& publicKey) {
    if (publicKey.size() < 64) return "";
    
    // Hash SHA-256 de la public key (omitimos el primer byte que indica compresión)
    vector<uint8_t> pubKeyData(publicKey.begin() + 1, publicKey.end());
    vector<uint8_t> sha256Hash = hexDecode(sha256(pubKeyData));
    
    // RIPEMD-160 del SHA-256
    unsigned char ripemd160Hash[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160_CTX ripemd160;
    
    RIPEMD160_Init(&ripemd160);
    RIPEMD160_Update(&ripemd160, sha256Hash.data(), sha256Hash.size());
    RIPEMD160_Final(ripemd160Hash, &ripemd160);
    
    // Tomamos los últimos 20 bytes como dirección
    stringstream ss;
    for (int i = 0; i < 20; i++) { ss << hex << setw(2) << setfill('0') << (int)ripemd160Hash[i]; }
    
    return ss.str();
}

string CryptoUtils::publicKeyToAddress(const string& publicKeyBase64) {
    // 1️⃣ Decodificar Base64
    vector<uint8_t> pubKeyBytes = base64Decode(publicKeyBase64);
    if (pubKeyBytes.empty()) return "";

    // 2️⃣ Hacer SHA-256
    unsigned char sha256Hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, pubKeyBytes.data(), pubKeyBytes.size());
    SHA256_Final(sha256Hash, &sha256);

    // 3️⃣ Hacer RIPEMD-160 sobre el hash SHA-256
    unsigned char ripemdHash[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160_CTX ripemd;
    RIPEMD160_Init(&ripemd);
    RIPEMD160_Update(&ripemd, sha256Hash, SHA256_DIGEST_LENGTH);
    RIPEMD160_Final(ripemdHash, &ripemd);

    // 4️⃣ Convertir a hexadecimal como "dirección"
    stringstream ss;
    for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)ripemdHash[i];
    }

    return ss.str();
}

bool CryptoUtils::isValidAddress(const string& addr) {
    // Regla simple: dirección no vacía, alfanumérica y >= 16 caracteres
    if (addr.empty()) return false;
    if (addr.size() < 16) return false;

    return all_of(addr.begin(), addr.end(), [](unsigned char c) {
        return isalnum(c); // solo letras y números
    });
}

// Validación
bool CryptoUtils::isValidPrivateKey(const string& privateKey) {
    try {
        // Decodificar la clave privada de Base64
        vector<uint8_t> privateKeyBytes = base64Decode(privateKey);
        
        // Verificar que tenga un tamaño válido para secp256k1 (32 bytes)
        if (privateKeyBytes.size() != 32) return false;
        
        // Convertir a BIGNUM y verificar que esté en el rango válido
        BIGNUM* privKeyBN = BN_bin2bn(privateKeyBytes.data(), privateKeyBytes.size(), nullptr);
        if (!privKeyBN) return false;
        
        // Obtener el orden de la curva
        EC_KEY* ecKey = createECKey();
        if (!ecKey) {
            BN_free(privKeyBN);
            return false;
        }
        
        const EC_GROUP* group = EC_KEY_get0_group(ecKey);
        BIGNUM* order = BN_new();
        EC_GROUP_get_order(group, order, nullptr);
        
        // La clave privada debe estar en el rango [1, order-1]
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
        // Decodificar la clave pública de Base64
        vector<uint8_t> publicKeyBytes = base64Decode(publicKey);
        
        // Una clave pública secp256k1 sin comprimir debe tener 65 bytes
        // (0x04 + 32 bytes X + 32 bytes Y)
        if (publicKeyBytes.size() != 65) return false;
        
        // El primer byte debe ser 0x04 (formato sin comprimir)
        if (publicKeyBytes[0] != 0x04) return false;
        
        // Verificar que la clave pública es un punto válido en la curva
        EC_KEY* ecKey = createECKey();
        if (!ecKey) return false;
        
        EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        EC_POINT* point = EC_POINT_new(group);
        
        // Convertir los bytes a punto EC
        int result = EC_POINT_oct2point(group, point, publicKeyBytes.data(), publicKeyBytes.size(), nullptr);
        
        // Verificar que el punto está en la curva
        bool isValid = (result == 1) && (EC_POINT_is_on_curve(group, point, nullptr) == 1);
        
        EC_POINT_free(point);
        EC_GROUP_free(group);
        EC_KEY_free(ecKey);
        
        return isValid;
    } catch (...) {
        return false;
    }
}

// Helper functions
EC_KEY* CryptoUtils::createECKey() {
    EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ecKey) return nullptr;
    return ecKey;
}

bool CryptoUtils::generateKeyPair(EC_KEY* ecKey) {
    if (!ecKey) return false;
    return EC_KEY_generate_key(ecKey) == 1;
}