#ifndef SIGNATURE_MANAGER_H
#define SIGNATURE_MANAGER_H

#include "Types.hpp"
#include "CryptoBase.hpp"
#include "KeyManager.hpp"
#include <vector>
#include <string>
#include <cstdint>
#include <stdexcept>
#include <algorithm>

class SignatureManager {
public:    
    // Inicialización (solo una vez al inicio del programa)
    static bool initialize();
    
    // Firma - versiones seguras
    static bool signMessage(const std::vector<uint8_t>& privateKey,
                          const std::vector<uint8_t>& message,
                          std::vector<uint8_t>& signature);
    
    static std::string signMessageEncoded(const std::string& privateKeyBase64,
                                        const std::vector<uint8_t>& message);
    
    // Verificación - API unificada y segura
    static bool verifySignature(const std::vector<uint8_t>& publicKey,
                              const std::vector<uint8_t>& message,
                              const std::vector<uint8_t>& signature);
    
    static bool verifySignatureEncoded(const std::string& publicKeyBase64,
                                     const std::vector<uint8_t>& message,
                                     const std::string& signatureBase64);
    
    // Utilidades de validación
    static bool isValidSignature(const std::vector<uint8_t>& signature);
    static bool isValidSignatureEncoded(const std::string& signatureBase64);

    static void secureClean(std::vector<uint8_t>& sensitiveData);

private:
    // Helpers internos
    static bool validateInputSizes(const std::vector<uint8_t>& publicKey,
                                 const std::vector<uint8_t>& privateKey,
                                 const std::vector<uint8_t>& signature);
};

#endif // SIGNATURE_MANAGER_H