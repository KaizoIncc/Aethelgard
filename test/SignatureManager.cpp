#include "SignatureManager.hpp"

bool SignatureManager::initialize() {
    bool result = CryptoBase::initialize();
    if (!result) {
        std::cerr << "Error: Failed to initialize SignatureManager - CryptoBase initialization failed" << std::endl;
    }
    return result;
}

bool SignatureManager::signMessage(const std::vector<uint8_t>& privateKey,
                                 const std::vector<uint8_t>& message,
                                 std::vector<uint8_t>& signature) {
    // ✅ DELEGAR validación a KeyManager
    if (!KeyManager::isValidPrivateKey(privateKey)) {
        std::cerr << "Error: Invalid private key provided to signMessage" << std::endl;
        return false;
    }
    
    if (message.empty()) {
        std::cerr << "Error: Cannot sign empty message" << std::endl;
        return false;
    }
    
    if (signature.size() != SIGNATURE_SIZE) {
        signature.resize(SIGNATURE_SIZE);
    }
    
    // Limpiar buffer de firma antes de usar
    CryptoBase::secureClean(signature);
    
    // Realizar la firma
    int result = crypto_sign_detached(signature.data(), nullptr,
                                    message.data(), message.size(), 
                                    privateKey.data());
    
    if (result != 0) {
        std::cerr << "Error: crypto_sign_detached failed with code: " << result << std::endl;
        CryptoBase::secureClean(signature);
        return false;
    }
    
    return true;
}

std::string SignatureManager::signMessageEncoded(const std::string& privateKeyBase64,
                                               const std::vector<uint8_t>& message) {
    // ✅ DELEGAR validación a KeyManager
    if (!KeyManager::isValidPrivateKeyEncoded(privateKeyBase64)) {
        std::cerr << "Error: Invalid encoded private key provided" << std::endl;
        return "";
    }
    
    if (message.empty()) {
        std::cerr << "Error: Empty message provided" << std::endl;
        return "";
    }
    
    std::vector<uint8_t> privateKeyBytes;
    try {
        privateKeyBytes = CryptoBase::base64Decode(privateKeyBase64);
    } catch (const std::exception& e) {
        std::cerr << "Error decoding private key: " << e.what() << std::endl;
        return "";
    }
    
    // Crear firma
    std::vector<uint8_t> signature(SIGNATURE_SIZE);
    bool success = signMessage(privateKeyBytes, message, signature);
    
    // Limpiar memoria sensible inmediatamente
    CryptoBase::secureClean(privateKeyBytes);
    
    if (success) {
        std::string signatureBase64 = CryptoBase::base64Encode(signature);
        CryptoBase::secureClean(signature);
        return signatureBase64;
    }
    
    CryptoBase::secureClean(signature);
    return "";
}

bool SignatureManager::verifySignature(const std::vector<uint8_t>& publicKey,
                                     const std::vector<uint8_t>& message,
                                     const std::vector<uint8_t>& signature) {
    if (!KeyManager::isValidPublicKey(publicKey)) {
        std::cerr << "Error: Invalid public key provided to verifySignature" << std::endl;
        return false;
    }
    
    if (!isValidSignature(signature)) {
        std::cerr << "Error: Invalid signature provided to verifySignature" << std::endl;
        return false;
    }
    
    if (message.empty()) {
        std::cerr << "Error: Cannot verify signature for empty message" << std::endl;
        return false;
    }
    
    // Verificar firma usando libsodium
    int result = crypto_sign_verify_detached(signature.data(),
                                           message.data(), message.size(),
                                           publicKey.data());
    
    if (result != 0) {
        if (result == -1) {
            std::cerr << "Warning: Signature verification failed - invalid signature" << std::endl;
        } else {
            std::cerr << "Error: Signature verification failed with code: " << result << std::endl;
        }
        return false;
    }
    
    return true;
}

bool SignatureManager::verifySignatureEncoded(const std::string& publicKeyBase64,
                                            const std::vector<uint8_t>& message,
                                            const std::string& signatureBase64) {
    // ✅ DELEGAR validación a KeyManager
    if (!KeyManager::isValidPublicKeyEncoded(publicKeyBase64)) {
        std::cerr << "Error: Invalid encoded public key provided" << std::endl;
        return false;
    }
    
    if (!isValidSignatureEncoded(signatureBase64)) {
        std::cerr << "Error: Invalid encoded signature provided" << std::endl;
        return false;
    }
    
    if (message.empty()) {
        std::cerr << "Error: Empty message provided" << std::endl;
        return false;
    }
    
    std::vector<uint8_t> publicKeyBytes;
    std::vector<uint8_t> signatureBytes;
    
    try {
        publicKeyBytes = CryptoBase::base64Decode(publicKeyBase64);
        signatureBytes = CryptoBase::base64Decode(signatureBase64);
    } catch (const std::exception& e) {
        std::cerr << "Error decoding base64 data: " << e.what() << std::endl;
        CryptoBase::secureClean(publicKeyBytes);
        CryptoBase::secureClean(signatureBytes);
        return false;
    }
    
    // Verificar firma
    bool result = verifySignature(publicKeyBytes, message, signatureBytes);
    
    // Limpiar memoria
    CryptoBase::secureClean(publicKeyBytes);
    CryptoBase::secureClean(signatureBytes);
    
    return result;
}

bool SignatureManager::isValidSignature(const std::vector<uint8_t>& signature) {
    if (signature.size() != SIGNATURE_SIZE) {
        return false;
    }
    
    // Verificar que no sea toda ceros
    if (std::all_of(signature.begin(), signature.end(), [](uint8_t b) { return b == 0; })) {
        return false;
    }
    
    // Verificación adicional: patrones simples que podrían indicar firma inválida
    // Por ejemplo, si todos los bytes son iguales (excepto ceros ya verificados)
    uint8_t firstByte = signature[0];
    if (std::all_of(signature.begin() + 1, signature.end(), 
                   [firstByte](uint8_t b) { return b == firstByte; })) {
        return false;
    }
    
    return true;
}

bool SignatureManager::isValidSignatureEncoded(const std::string& signatureBase64) {
    if (signatureBase64.empty()) {
        return false;
    }
    
    try {
        std::vector<uint8_t> signatureBytes = CryptoBase::base64Decode(signatureBase64);
        bool isValid = isValidSignature(signatureBytes);
        CryptoBase::secureClean(signatureBytes);
        return isValid;
    } catch (const std::exception& e) {
        std::cerr << "Error validating encoded signature: " << e.what() << std::endl;
        return false;
    }
}

void SignatureManager::secureClean(std::vector<uint8_t>& sensitiveData) {
    CryptoBase::secureClean(sensitiveData);
}