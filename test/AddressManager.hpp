#ifndef ADDRESS_MANAGER_H
#define ADDRESS_MANAGER_H

#include "CryptoBase.hpp"
#include "Types.hpp"
#include "KeyManager.hpp"
#include <string>
#include <vector>
#include <cstdint>

class AddressManager {
public:
    // Generación de direcciones desde claves públicas
    static std::string getAddressFromPublicKey(const std::vector<uint8_t>& publicKey);
    static std::string getAddressFromEncodedPublicKey(const std::string& publicKeyBase64);
    
    // Validación
    static bool isValidAddress(const std::string& address);
    
    // Utilidades
    static std::string normalizeAddress(const std::string& address);

    static void secureClean(std::vector<uint8_t>& sensitiveData);
    static void secureClean(std::string& sensitiveData);

private:
    // Helpers internos
    static bool validateAddressFormat(const std::string& address);
};

#endif // ADDRESS_MANAGER_H