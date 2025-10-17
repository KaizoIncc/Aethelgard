#include "CryptoBase.hpp"

// -----------------------------------------------------------------------------------
// ---------------------------- PRIVATE METHODS --------------------------------------
// -----------------------------------------------------------------------------------

namespace {
    const std::string B64_CHARS = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // Tabla para decodificación base64
    std::vector<int> buildDecodeTable() {
        std::vector<int> decode_table(256, -1);
        for (size_t i = 0; i < B64_CHARS.size(); ++i) {
            decode_table[static_cast<unsigned char>(B64_CHARS[i])] = static_cast<int>(i);
        }
        return decode_table;
    }

    // Función helper para validar caracteres hexadecimales
    bool isValidHexChar(char c) {
        return (c >= '0' && c <= '9') || 
               (c >= 'a' && c <= 'f') || 
               (c >= 'A' && c <= 'F');
    }

    // Función helper para validar string base64
    bool isValidBase64Char(char c) {
        return (c >= 'A' && c <= 'Z') ||
               (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') ||
               (c == '+') || (c == '/') ||
               (c == '=');
    }
}

bool CryptoBase::initialize() {
    if (sodium_init() < 0) {
        std::cerr << "ERROR: Failed to initialize libsodium" << std::endl;
        return false;
    }
    
    return true;
}

std::string CryptoBase::fastBase64Encode(const std::vector<uint8_t>& data) {
    if (data.empty()) return "";

    std::string result;
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

std::vector<uint8_t> CryptoBase::fastBase64Decode(const std::string& encoded) {
    if (encoded.empty()) return {};

    // Validación básica de entrada base64
    for (char c : encoded) {
        if (!isValidBase64Char(c)) {
            throw std::invalid_argument("Invalid base64 character: " + std::string(1, c));
        }
    }

    static std::vector<int> decode_table = buildDecodeTable();

    std::vector<uint8_t> result;
    result.reserve((encoded.size() * 3) / 4);

    int value = 0;
    int bits = -8;
    
    for (unsigned char c : encoded) {
        if (c == '=') break;
        
        int digit = decode_table[c];
        if (digit == -1) {
            // Esto no debería pasar gracias a la validación anterior
            continue;
        }

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

std::vector<uint8_t> CryptoBase::sha256Bytes(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(crypto_hash_sha256_BYTES);
    
    // crypto_hash_sha256 puede manejar data.data() incluso cuando data.size() es 0
    if (crypto_hash_sha256(hash.data(), data.data(), data.size()) != 0) {
        throw std::runtime_error("SHA-256 computation failed");
    }
    
    return hash;
}

std::string CryptoBase::sha256(const std::string& data) {
    // Para strings, tratamos como datos binarios (no texto)
    std::vector<uint8_t> dataVec(data.begin(), data.end());
    return sha256(dataVec);
}

std::string CryptoBase::sha256(const std::vector<uint8_t>& data) {
    auto hash = sha256Bytes(data);
    
    std::stringstream hexStream;
    hexStream << std::hex << std::setfill('0');
    
    for (uint8_t byte : hash) {
        hexStream << std::setw(2) << static_cast<int>(byte);
    }
    
    return hexStream.str();
}

// Codificación/Decodificación
std::string CryptoBase::base64Encode(const std::vector<uint8_t>& data) {
    return fastBase64Encode(data);
}

std::vector<uint8_t> CryptoBase::base64Decode(const std::string& encoded) {
    try {
        return fastBase64Decode(encoded);
    } catch (const std::exception& e) {
        std::cerr << "Base64 decode error: " << e.what() << std::endl;
        throw;
    }
}

std::string CryptoBase::hexEncode(const std::vector<uint8_t>& data) {
    std::stringstream hexStream;
    hexStream << std::hex << std::setfill('0');
    
    for (uint8_t byte : data) {
        hexStream << std::setw(2) << static_cast<int>(byte);
    }
    
    return hexStream.str();
}

std::vector<uint8_t> CryptoBase::hexDecode(const std::string& hexStr) {
    // Validación de entrada
    if (hexStr.empty()) {
        return {};
    }
    
    if (hexStr.length() % 2 != 0) {
        throw std::invalid_argument("Hex string must have even length");
    }
    
    // Validar caracteres hexadecimales
    for (char c : hexStr) {
        if (!isValidHexChar(c)) {
            throw std::invalid_argument("Invalid hex character: " + std::string(1, c));
        }
    }
    
    std::vector<uint8_t> bytes;
    bytes.reserve(hexStr.length() / 2);
    
    for (size_t i = 0; i < hexStr.length(); i += 2) {
        std::string byteString = hexStr.substr(i, 2);
        
        try {
            // Usar stoul para mejor manejo de errores
            uint8_t byte = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
            bytes.push_back(byte);
        } catch (const std::exception& e) {
            throw std::invalid_argument("Failed to parse hex byte: " + byteString);
        }
    }
    
    return bytes;
}

std::string CryptoBase::bytesToHex(const std::vector<uint8_t>& data) {
    return hexEncode(data);
}

// Utilidades de seguridad
void CryptoBase::secureClean(std::vector<uint8_t>& sensitiveData) {
    if (!sensitiveData.empty()) {
        sodium_memzero(sensitiveData.data(), sensitiveData.size()); // Liberar memoria
    }
}

void CryptoBase::secureClean(std::string& sensitiveData) {
    if (!sensitiveData.empty()) {
        // Para strings, overwrite y luego limpiar
        sodium_memzero(&sensitiveData[0], sensitiveData.size());
    }
}

bool CryptoBase::ed25519SeedKeypair(std::vector<uint8_t>& publicKey, 
                                   std::vector<uint8_t>& privateKey, 
                                   const std::vector<uint8_t>& seed) {
    // Asegurar tamaños correctos
    if (publicKey.size() != 32) publicKey.resize(32);
    if (privateKey.size() != 64) privateKey.resize(64);
    if (seed.size() != 32) {
        std::cerr << "ERROR: Seed must be 32 bytes" << std::endl;
        return false;
    }
    
    // Llamar a la función correcta de libsodium
    int result = crypto_sign_ed25519_seed_keypair(publicKey.data(), privateKey.data(), seed.data());
    
    return result == 0;
}

int CryptoBase::ed25519SkToPk(std::vector<uint8_t>& publicKey, const std::vector<uint8_t>& privateKey) {
    return crypto_sign_ed25519_sk_to_pk(publicKey.data(), privateKey.data());
}

bool CryptoBase::randomBytes(std::vector<uint8_t>& buffer) {
    if (buffer.empty()) {
        return true; // Nada que hacer para buffer vacío
    }
    
    return randomBytes(buffer.data(), buffer.size());
}

bool CryptoBase::randomBytes(uint8_t* buffer, size_t size) {
    if (buffer == nullptr) {
        std::cerr << "Error: Null buffer provided to randomBytes" << std::endl;
        return false;
    }
    
    if (size == 0) {
        return true; // Nada que generar
    }
    
    // Verificar que libsodium esté inicializado
    if (sodium_init() < 0) {
        std::cerr << "Error: libsodium not initialized in randomBytes" << std::endl;
        return false;
    }
    
    // Generar bytes aleatorios usando la función segura de libsodium
    randombytes_buf(buffer, size);
    
    return true;
}

bool CryptoBase::isRandomGeneratorAvailable() {
    // Verificar que libsodium esté inicializado
    if (sodium_init() < 0) {
        return false;
    }
    
    return true;
}