#ifndef CRYPTO_BASE_H
#define CRYPTO_BASE_H

#include <vector>
#include <string>
#include <cstdint>
#include <sodium.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <cstring>
#include "Types.hpp"
#include <cctype>
#include <iostream>

class CryptoBase {
public:
    // Inicialización (una sola vez al inicio)
    static bool initialize();
    
    // Hashing con libsodium (más rápido)
    static std::string sha256(const std::string& data);
    static std::string sha256(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> sha256Bytes(const std::vector<uint8_t>& data);
    
    // Codificación/Decodificación (se mantienen igual - son eficientes)
    static std::string base64Encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> base64Decode(const std::string& encoded);
    static std::string hexEncode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> hexDecode(const std::string& hexStr);
    static std::string bytesToHex(const std::vector<uint8_t>& data);

    // Utilidades de seguridad
    static void secureClean(std::vector<uint8_t>& sensitiveData);
    static void secureClean(std::string& sensitiveData);

    // Helpers criptográficos específicos para KeyManager
    static bool ed25519SeedKeypair(std::vector<uint8_t>& publicKey, std::vector<uint8_t>& privateKey, const std::vector<uint8_t>& seed);
    static int ed25519SkToPk(std::vector<uint8_t>& publicKey, const std::vector<uint8_t>& privateKey);

    // Generación de bytes aleatorios
    static bool randomBytes(std::vector<uint8_t>& buffer);
    static bool randomBytes(uint8_t* buffer, size_t size);
    static bool isRandomGeneratorAvailable();

private:
    // Helpers internos para base64 (se mantienen igual)
    static std::string fastBase64Encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> fastBase64Decode(const std::string& encoded);
};

#endif