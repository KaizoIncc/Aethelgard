#ifndef KEY_MANAGER_H
#define KEY_MANAGER_H

#include "CryptoBase.hpp"
#include "Types.hpp"
#include <vector>
#include <string>
#include <cstdint>
#include <algorithm>
#include <stdexcept>
#include <iostream>

class KeyManager {
public:
    // Generación de claves - versiones seguras
    static bool generateKeyPairSecure(std::string& privateKeyEncoded, std::string& publicKeyEncoded);
    static bool generateKeyPair(std::vector<uint8_t>& privateKey, std::vector<uint8_t>& publicKey);
    
    // Derivación de clave pública desde privada
    static bool derivePublicKey(const std::vector<uint8_t>& privateKey, std::vector<uint8_t>& publicKey);
    static std::string derivePublicKeyFromEncoded(const std::string& privateKeyBase64);
    
    // Validación robusta
    static bool isValidPrivateKey(const std::vector<uint8_t>& privateKey);
    static bool isValidPublicKey(const std::vector<uint8_t>& publicKey);
    static bool isValidPrivateKeyEncoded(const std::string& privateKey);
    static bool isValidPublicKeyEncoded(const std::string& publicKey);
    
    // Utilidades de seguridad
    static void secureClean(std::vector<uint8_t>& sensitiveData);
};

#endif // KEY_MANAGER_H