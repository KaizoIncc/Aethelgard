#include "KeyManager.hpp"

using namespace std;

bool KeyManager::generateKeyPair(string& privateKey, string& publicKey) {
    // ¡Simplemente delega a CryptoBase!
    return CryptoBase::generateKeyPair(privateKey, publicKey);
}

bool KeyManager::generateKeyPair(vector<uint8_t>& privateKey, vector<uint8_t>& publicKey) {
    // ¡Simplemente delega a CryptoBase!
    return CryptoBase::generateKeyPair(privateKey, publicKey);
}

string KeyManager::derivePublicKey(const string& privateKeyBase64) {
    vector<uint8_t> privateKeyBytes = CryptoBase::base64Decode(privateKeyBase64);
    
    if (privateKeyBytes.size() == 32) {
        // Es una semilla - generar par de claves completo
        vector<uint8_t> publicKey(32);
        vector<uint8_t> privateKeyFull(64);
        
        if (crypto_sign_seed_keypair(publicKey.data(), privateKeyFull.data(), 
                                    privateKeyBytes.data()) != 0) {
            return "";
        }
        return CryptoBase::base64Encode(publicKey);
        
    } else if (privateKeyBytes.size() == 64) {
        // Es una clave privada completa - extraer solo la pública
        vector<uint8_t> publicKey(32);
        
        if (crypto_sign_ed25519_sk_to_pk(publicKey.data(), privateKeyBytes.data()) != 0) {
            return "";
        }
        return CryptoBase::base64Encode(publicKey);
        
    } else {
        return ""; // Tamaño inválido
    }
}

bool KeyManager::isValidPrivateKey(const string& privateKey) {
    try {
        vector<uint8_t> privateKeyBytes = CryptoBase::base64Decode(privateKey);
        
        // Aceptar tanto semillas (32 bytes) como claves privadas completas (64 bytes)
        return (privateKeyBytes.size() == 32 || privateKeyBytes.size() == 64) && 
               !all_of(privateKeyBytes.begin(), privateKeyBytes.end(), 
                      [](uint8_t b) { return b == 0; });
    } catch (...) {
        return false;
    }
}

bool KeyManager::isValidPublicKey(const string& publicKey) {
    try {
        vector<uint8_t> publicKeyBytes = CryptoBase::base64Decode(publicKey);
        
        // En Ed25519, las claves públicas son exactamente 32 bytes
        // No hay formato de compresión que verificar
        return publicKeyBytes.size() == 32;
        
        // Nota: En una implementación completa, podríamos verificar
        // que el punto está en la curva, pero libsodium ya lo hace
        // automáticamente en las operaciones de firma/verificación
    } catch (...) {
        return false;
    }
}