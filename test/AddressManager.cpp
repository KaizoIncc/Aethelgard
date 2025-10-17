#include "AddressManager.hpp"

std::string AddressManager::getAddressFromPublicKey(const std::vector<uint8_t>& publicKey) {
    // Validación exhaustiva de la clave pública
    if (!KeyManager::isValidPublicKey(publicKey)) {
        throw std::invalid_argument("Invalid public key format");
    }
    
    // Calcular SHA-256 de la clave pública
    std::vector<uint8_t> hash = CryptoBase::sha256Bytes(publicKey);
    
    // Verificar que el hash tenga tamaño suficiente
    if (hash.size() < ADDRESS_SIZE) {
        throw std::runtime_error("SHA-256 hash too short for address derivation");
    }
    
    // Tomar los últimos 20 bytes para la dirección (estilo Ethereum)
    std::vector<uint8_t> addressBytes(hash.end() - ADDRESS_SIZE, hash.end());
    
    // Convertir a hexadecimal
    std::string address = CryptoBase::hexEncode(addressBytes);
    
    // Verificar que la dirección generada sea válida
    if (!isValidAddress(address)) {
        throw std::runtime_error("Generated address is invalid");
    }
    
    return address;
}

std::string AddressManager::getAddressFromEncodedPublicKey(const std::string& publicKeyBase64) {
    // Validación de entrada
    if (publicKeyBase64.empty()) {
        throw std::invalid_argument("Empty public key provided");
    }
    
    std::vector<uint8_t> publicKeyBytes;
    try {
        publicKeyBytes = CryptoBase::base64Decode(publicKeyBase64);
    } catch (const std::exception& e) {
        throw std::invalid_argument("Failed to decode public key: " + std::string(e.what()));
    }
    
    // Generar dirección
    std::string address = getAddressFromPublicKey(publicKeyBytes);
    
    // Limpiar memoria sensible
    CryptoBase::secureClean(publicKeyBytes);
    
    return address;
}

bool AddressManager::isValidAddress(const std::string& address) {
    // Validación de formato básico
    if (!validateAddressFormat(address)) {
        return false;
    }
    
    // Validación adicional: checksum (opcional para Ethereum-style addresses)
    // En una implementación completa, se podría implementar checksum EIP-55
    return true;
}

std::string AddressManager::normalizeAddress(const std::string& address) {
    if (!isValidAddress(address)) {
        throw std::invalid_argument("Cannot normalize invalid address");
    }
    
    // Convertir a minúsculas para consistencia
    // Nota: En Ethereum se usaría checksum EIP-55, pero para simplicidad usamos minúsculas
    std::string normalized = address;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                  [](unsigned char c) { return std::tolower(c); });
    
    return normalized;
}

bool AddressManager::validateAddressFormat(const std::string& address) {
    // Check if address is exactly 40 characters (20 bytes in hex)
    if (address.length() != ADDRESS_HEX_LENGTH) {
        return false;
    }
    
    // Check if all characters are valid hex digits
    for (char c : address) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    
    return true;
}

void AddressManager::secureClean(std::vector<uint8_t>& sensitiveData) {
    CryptoBase::secureClean(sensitiveData);
}

void AddressManager::secureClean(std::string& sensitiveData) {
    CryptoBase::secureClean(sensitiveData);
}