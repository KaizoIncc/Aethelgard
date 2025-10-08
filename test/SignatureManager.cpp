#include "SignatureManager.hpp"

using namespace std;

bool SignatureManager::initialize() {
    return CryptoBase::initialize();
}

string SignatureManager::signMessage(const string& privateKey, const string& messageHex) {
    vector<uint8_t> privateKeyBytes = CryptoBase::base64Decode(privateKey);
    
    // CORRECCIÓN: Convertir el hash hexadecimal a bytes
    vector<uint8_t> messageBytes = CryptoBase::hexDecode(messageHex);
    
    vector<uint8_t> signature = signMessage(privateKeyBytes, messageBytes);
    
    return CryptoBase::base64Encode(signature);
}

vector<uint8_t> SignatureManager::signMessage(const vector<uint8_t>& privateKey,
                                         const vector<uint8_t>& message) {
    if (privateKey.size() != PRIVATE_KEY_SIZE) {
        return {};
    }

    vector<uint8_t> signature(SIGNATURE_SIZE);
    
    if (crypto_sign_detached(signature.data(), nullptr,
                           message.data(), message.size(), 
                           privateKey.data()) != 0) {
        return {};
    }

    return signature;
}

// Para mensajes en formato vector<uint8_t>
bool SignatureManager::verifySignature(const string& publicKey, const vector<uint8_t>& message, 
                                      const string& signatureBase64) {
    vector<uint8_t> publicKeyBytes = CryptoBase::base64Decode(publicKey);
    vector<uint8_t> signatureBytes = CryptoBase::base64Decode(signatureBase64);
    
    if (publicKeyBytes.size() != PUBLIC_KEY_SIZE || signatureBytes.size() != SIGNATURE_SIZE) {
        return false;
    }
    
    return crypto_sign_verify_detached(signatureBytes.data(),
                                     message.data(), message.size(),
                                     publicKeyBytes.data()) == 0;
}

// Para parámetros completamente en binario
bool SignatureManager::verifySignature(const vector<uint8_t>& publicKey,
                                     const vector<uint8_t>& message,
                                     const vector<uint8_t>& signature) {
    if (publicKey.size() != PUBLIC_KEY_SIZE || signature.size() != SIGNATURE_SIZE) {
        return false;
    }
    
    return crypto_sign_verify_detached(signature.data(),
                                     message.data(), message.size(),
                                     publicKey.data()) == 0;
}

// Para mensajes en formato string normal (texto plano)
bool SignatureManager::verifySignatureString(const string& publicKey, const string& message, 
                                           const string& signatureBase64) {
    vector<uint8_t> publicKeyBytes = CryptoBase::base64Decode(publicKey);
    vector<uint8_t> signatureBytes = CryptoBase::base64Decode(signatureBase64);
    
    if (publicKeyBytes.size() != PUBLIC_KEY_SIZE || signatureBytes.size() != SIGNATURE_SIZE) {
        return false;
    }
    
    // Convertir el mensaje string a bytes
    vector<uint8_t> messageBytes(message.begin(), message.end());
    
    return crypto_sign_verify_detached(signatureBytes.data(),
                                     messageBytes.data(), messageBytes.size(),
                                     publicKeyBytes.data()) == 0;
}

// Para mensajes en formato hexadecimal (hashes)
bool SignatureManager::verifySignatureHex(const string& publicKey, const string& messageHex, 
                                        const string& signatureBase64) {
    // Convertir hash hexadecimal a bytes
    vector<uint8_t> messageBytes = CryptoBase::hexDecode(messageHex);
    if (messageBytes.empty()) {
        return false;
    }
    
    return verifySignature(publicKey, messageBytes, signatureBase64);
}