#include "CryptoBase.hpp"

using namespace std;

// -----------------------------------------------------------------------------------
// ---------------------------- CryptoBase Implementation ----------------------------
// -----------------------------------------------------------------------------------

// -----------------------------------------------------------------------------------
// ---------------------------- PRIVATE METHODS --------------------------------------
// -----------------------------------------------------------------------------------

namespace {
    const string B64_CHARS = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // Tabla para decodificación base64
    vector<int> buildDecodeTable() {
        vector<int> decode_table(256, -1);
        for (size_t i = 0; i < B64_CHARS.size(); ++i) {
            decode_table[(unsigned char)B64_CHARS[i]] = i;
        }
        return decode_table;
    }
}

bool CryptoBase::initialize() {
    // ¡Una sola línea para inicializar toda la criptografía!
    return sodium_init() >= 0;
}

string CryptoBase::fastBase64Encode(const vector<uint8_t>& data) {
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

vector<uint8_t> CryptoBase::fastBase64Decode(const string& encoded) {
    static vector<int> decode_table = buildDecodeTable();

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

// -----------------------------------------------------------------------------------
// ---------------------------- PUBLIC METHODS ---------------------------------------
// -----------------------------------------------------------------------------------

// Hashing con libsodium (más rápido y simple)
vector<uint8_t> CryptoBase::sha256Bytes(const vector<uint8_t>& data) {
    vector<uint8_t> hash(crypto_hash_sha256_BYTES); // 32 bytes
    
    crypto_hash_sha256(hash.data(), data.data(), data.size());
    return hash;
}

string CryptoBase::sha256(const string& data) {
    return sha256(vector<uint8_t>(data.begin(), data.end()));
}

string CryptoBase::sha256(const vector<uint8_t>& data) {
    auto hash = sha256Bytes(data);
    
    stringstream hexStream;
    for (uint8_t byte : hash) {
        hexStream << hex << setw(2) << setfill('0') << static_cast<int>(byte);
    }
    
    return hexStream.str();
}

// Generación de claves Ed25519 (¡DRAMÁTICAMENTE más simple!)
bool CryptoBase::generateKeyPair(vector<uint8_t>& privateKey, vector<uint8_t>& publicKey) {
    privateKey.resize(32);  // Ed25519 private key size
    publicKey.resize(32);   // Ed25519 public key size
    
    return crypto_sign_keypair(publicKey.data(), privateKey.data()) == 0;
}

bool CryptoBase::generateKeyPair(string& privateKey, string& publicKey) {
    vector<uint8_t> priv(32), pub(32);
    
    if (!generateKeyPair(priv, pub)) {
        return false;
    }
    
    privateKey = base64Encode(priv);
    publicKey = base64Encode(pub);
    return true;
}

// Derivación de dirección (SIMPLIFICADO - estilo Ethereum)
string CryptoBase::getAddressFromPublicKey(const vector<uint8_t>& publicKey) {
    if (publicKey.size() != 32) {
        return "";  // Validación Ed25519
    }
    
    // SHA-256 de la clave pública y tomar últimos 20 bytes
    // (similar a Ethereum pero con Ed25519 en lugar de secp256k1)
    auto hash = sha256Bytes(publicKey);
    
    // Tomar los últimos 20 bytes para la dirección
    // Esto es más seguro que tomar los primeros
    vector<uint8_t> addressBytes(hash.end() - 20, hash.end());
    
    return hexEncode(addressBytes);
}

// Codificación/Decodificación (se mantienen igual)
string CryptoBase::base64Encode(const vector<uint8_t>& data) {
    return fastBase64Encode(data);
}

vector<uint8_t> CryptoBase::base64Decode(const string& encoded) {
    return fastBase64Decode(encoded);
}

string CryptoBase::hexEncode(const vector<uint8_t>& data) {
    stringstream hexStream;
    for (uint8_t byte : data) {
        hexStream << hex << setw(2) << setfill('0') << static_cast<int>(byte);
    }
    return hexStream.str();
}

vector<uint8_t> CryptoBase::hexDecode(const string& hexStr) {
    vector<uint8_t> bytes;
    
    if (hexStr.length() % 2 != 0) {
        return {}; // Longitud impar no válida
    }
    
    for (size_t i = 0; i < hexStr.length(); i += 2) {
        string byteString = hexStr.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    
    return bytes;
}