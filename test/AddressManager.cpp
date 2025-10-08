#include "AddressManager.hpp"

string AddressManager::getAddressFromPublicKey(const string& publicKey) {
    vector<uint8_t> publicKeyBytes = CryptoBase::base64Decode(publicKey);
    return getAddressFromPublicKey(publicKeyBytes);
}

string AddressManager::getAddressFromPublicKey(const vector<uint8_t>& publicKey) {
    // ¡Validación simple! Ed25519 son 32 bytes
    if (publicKey.size() != 32) return "";
    
    // SHA-256 de la clave pública y tomar últimos 20 bytes
    // (Estilo Ethereum pero con Ed25519)
    auto hash = CryptoBase::sha256Bytes(publicKey);
    vector<uint8_t> addressBytes(hash.end() - 20, hash.end());
    
    return CryptoBase::hexEncode(addressBytes);
}

string AddressManager::publicKeyToAddress(const string& publicKeyBase64) {
    // ¡Sin caché necesaria! La operación es muy rápida ahora
    return getAddressFromPublicKey(publicKeyBase64);
}

bool AddressManager::isValidAddress(const string& address) {
    // Dirección debe ser hexadecimal de 40 caracteres (20 bytes)
    if (address.length() != 40) return false;
    
    // Todos los caracteres deben ser hexadecimales
    return all_of(address.begin(), address.end(), [](unsigned char c) {
        return isxdigit(c);
    });
}