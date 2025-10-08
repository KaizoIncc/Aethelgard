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
    // Con Ed25519, la clave pública se deriva trivialmente
    // Pero en libsodium, necesitamos generarla desde la privada
    
    vector<uint8_t> privateKeyBytes = CryptoBase::base64Decode(privateKeyBase64);
    if (privateKeyBytes.size() != 32) return "";
    
    vector<uint8_t> publicKey(32);
    
    // Derivar clave pública desde privada
    if (crypto_sign_ed25519_sk_to_pk(publicKey.data(), privateKeyBytes.data()) != 0) {
        return "";
    }
    
    return CryptoBase::base64Encode(publicKey);
}

bool KeyManager::isValidPrivateKey(const string& privateKey) {
    try {
        vector<uint8_t> privateKeyBytes = CryptoBase::base64Decode(privateKey);
        
        // En Ed25519, cualquier secuencia de 32 bytes es válida
        // Pero verificamos que no sea todo ceros por seguridad
        return privateKeyBytes.size() == 32 && 
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