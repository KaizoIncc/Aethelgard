#include "KeyManager.hpp"

// Generación de claves Ed25519 - VERSIÓN SEGURA
bool KeyManager::generateKeyPair(std::vector<uint8_t>& privateKey, std::vector<uint8_t>& publicKey) {
    // VERIFICACIÓN ROBUSTA de los buffers
    if (privateKey.size() != PRIVATE_KEY_SIZE || publicKey.size() != PUBLIC_KEY_SIZE) {
        std::cerr << "Error: Invalid buffer sizes. Private: " << privateKey.size() 
                  << ", Public: " << publicKey.size() << std::endl;
        return false;
    }
    
    if (privateKey.data() == nullptr || publicKey.data() == nullptr) {
        std::cerr << "Error: Null buffer pointers detected" << std::endl;
        return false;
    }
    
    // GENERAR SEMILLA ALEATORIA usando CryptoBase
    std::vector<uint8_t> seed(SEED_SIZE);
    if (!CryptoBase::randomBytes(seed)) {
        std::cerr << "Error: Failed to generate random seed" << std::endl;
        return false;
    }
    
    // Generar par de claves con semilla aleatoria
    bool result = CryptoBase::ed25519SeedKeypair(publicKey, privateKey, seed);
    
    if (!result) {
        std::cerr << "Error: crypto_sign_ed25519_seed_keypair failed" << std::endl;
        secureClean(privateKey);
        secureClean(publicKey);
        return false;
    }
    
    return true;
}

// Versión segura que codifica las claves y limpia la memoria
bool KeyManager::generateKeyPairSecure(std::string& privateKeyEncoded, std::string& publicKeyEncoded) {
    std::vector<uint8_t> privateKey(PRIVATE_KEY_SIZE);
    std::vector<uint8_t> publicKey(PUBLIC_KEY_SIZE);
    
    // Limpiar strings de salida
    privateKeyEncoded.clear();
    publicKeyEncoded.clear();
    
    if (!generateKeyPair(privateKey, publicKey)) {
        return false;
    }
    
    // Codificar las claves
    privateKeyEncoded = CryptoBase::base64Encode(privateKey);
    publicKeyEncoded = CryptoBase::base64Encode(publicKey);
    
    // Limpiar memoria sensible inmediatamente después de usar
    secureClean(privateKey);
    secureClean(publicKey);
    
    return true;
}

bool KeyManager::derivePublicKey(const std::vector<uint8_t>& privateKey, std::vector<uint8_t>& publicKey) {
    // Validación de entrada
    if (privateKey.empty()) {
        return false;
    }
    
    // Verificar que la clave privada no sea toda ceros
    if (std::all_of(privateKey.begin(), privateKey.end(), [](uint8_t b) { return b == 0; })) {
        return false;
    }
    
    if (publicKey.size() != PUBLIC_KEY_SIZE) {
        publicKey.resize(PUBLIC_KEY_SIZE);
    }
    
    bool success = false;
    
    if (privateKey.size() == SEED_SIZE) {
        std::vector<uint8_t> privateKeyFull(PRIVATE_KEY_SIZE);
        // USAR CryptoBase en lugar de libsodium directamente:
        if (CryptoBase::ed25519SeedKeypair(publicKey, privateKeyFull, privateKey) == 0) {
            success = true;
        }
        secureClean(privateKeyFull);
    } else if (privateKey.size() == PRIVATE_KEY_SIZE) {
        // USAR CryptoBase en lugar de libsodium directamente:
        success = (CryptoBase::ed25519SkToPk(publicKey, privateKey) == 0);
    } else {
        // Tamaño inválido
        success = false;
    }
    
    if (!success) {
        // Limpiar salida en caso de error
        secureClean(publicKey);
    }
    
    return success;
}

std::string KeyManager::derivePublicKeyFromEncoded(const std::string& privateKeyBase64) {
    // Validación de entrada
    if (privateKeyBase64.empty()) {
        return "";
    }
    
    std::vector<uint8_t> privateKeyBytes;
    std::vector<uint8_t> publicKey(PUBLIC_KEY_SIZE);
    
    try {
        privateKeyBytes = CryptoBase::base64Decode(privateKeyBase64);
    } catch (const std::exception& e) {
        std::cerr << "Error decoding private key: " << e.what() << std::endl;
        return "";
    }
    
    bool success = derivePublicKey(privateKeyBytes, publicKey);
    
    // Limpiar memoria sensible inmediatamente
    secureClean(privateKeyBytes);
    
    if (success) {
        std::string publicKeyEncoded = CryptoBase::base64Encode(publicKey);
        secureClean(publicKey);
        return publicKeyEncoded;
    }
    
    secureClean(publicKey);
    return "";
}

bool KeyManager::isValidPrivateKey(const std::vector<uint8_t>& privateKey) {
    // Verificar tamaño
    if (privateKey.size() != SEED_SIZE && privateKey.size() != PRIVATE_KEY_SIZE) {
        return false;
    }
    
    // Verificar que no sean todos ceros
    if (std::all_of(privateKey.begin(), privateKey.end(), [](uint8_t b) { return b == 0; })) {
        return false;
    }
    
    // Para claves completas de 64 bytes, verificar que los últimos 32 bytes 
    // corresponden a la clave pública derivada de los primeros 32
    if (privateKey.size() == PRIVATE_KEY_SIZE) {
        std::vector<uint8_t> derivedPublicKey(PUBLIC_KEY_SIZE);
        std::vector<uint8_t> tempPrivateKey(PRIVATE_KEY_SIZE); // Temporary buffer for private key
        std::vector<uint8_t> seed(privateKey.begin(), privateKey.begin() + SEED_SIZE);
        
        // Verificar que la semilla no sea toda ceros
        if (std::all_of(seed.begin(), seed.end(), [](uint8_t b) { return b == 0; })) {
            secureClean(seed);
            return false;
        }
        
        // Use the temporary private key buffer instead of nullptr
        if (!CryptoBase::ed25519SeedKeypair(derivedPublicKey, tempPrivateKey, seed)) {
            secureClean(seed);
            secureClean(derivedPublicKey);
            secureClean(tempPrivateKey);
            return false;
        }
        
        // Comparar con los últimos 32 bytes de la clave privada
        bool isValid = std::equal(derivedPublicKey.begin(), derivedPublicKey.end(),
                                 privateKey.begin() + SEED_SIZE);
        
        secureClean(seed);
        secureClean(derivedPublicKey);
        secureClean(tempPrivateKey);
        return isValid;
    }
    
    return true;
}

bool KeyManager::isValidPublicKey(const std::vector<uint8_t>& publicKey) {
    // Verificar tamaño exacto
    if (publicKey.size() != PUBLIC_KEY_SIZE) {
        return false;
    }
    
    // Verificar que no sean todos ceros
    if (std::all_of(publicKey.begin(), publicKey.end(), [](uint8_t b) { return b == 0; })) {
        return false;
    }
    
    return true;
}

bool KeyManager::isValidPrivateKeyEncoded(const std::string& privateKey) {
    if (privateKey.empty()) {
        return false;
    }
    
    try {
        std::vector<uint8_t> privateKeyBytes = CryptoBase::base64Decode(privateKey);
        bool isValid = isValidPrivateKey(privateKeyBytes);
        secureClean(privateKeyBytes);
        return isValid;
    } catch (const std::exception& e) {
        std::cerr << "Error validating encoded private key: " << e.what() << std::endl;
        return false;
    }
}

bool KeyManager::isValidPublicKeyEncoded(const std::string& publicKey) {
    if (publicKey.empty()) {
        return false;
    }
    
    try {
        std::vector<uint8_t> publicKeyBytes = CryptoBase::base64Decode(publicKey);
        bool isValid = isValidPublicKey(publicKeyBytes);
        secureClean(publicKeyBytes);
        return isValid;
    } catch (const std::exception& e) {
        std::cerr << "Error validating encoded public key: " << e.what() << std::endl;
        return false;
    }
}

void KeyManager::secureClean(std::vector<uint8_t>& sensitiveData) {
    CryptoBase::secureClean(sensitiveData);
}