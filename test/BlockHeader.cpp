#include "BlockHeader.hpp"
#include <stdexcept>
#include <algorithm>
#include <chrono>
#include <iostream>

BlockHeader::BlockHeader(int64_t index, const std::vector<uint8_t>& previousHash) 
    : index(index), previousHash(previousHash) {
    
    // Validación de parámetros
    if (index < 0) {
        throw std::invalid_argument("Block index cannot be negative");
    }
    
    // Para el bloque génesis, permitir previousHash todo ceros
    if (index == 0) {
        if (previousHash.size() != SHA256_HASH_SIZE) {
            throw std::invalid_argument("Invalid previous hash format for genesis block");
        }
        // Génesis puede tener previousHash todo ceros, no verificamos el contenido
    } else {
        if (!isValidHash(previousHash)) {
            throw std::invalid_argument("Invalid previous hash format");
        }
    }
    
    // Establecer timestamp actual
    timestamp = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now()
    );
    
    // Inicializar hashes vacíos
    merkleRoot = std::vector<uint8_t>(SHA256_HASH_SIZE, 0);
    hash = std::vector<uint8_t>(SHA256_HASH_SIZE, 0);
}

// Getters
int64_t BlockHeader::getIndex() const { 
    return index; 
}

std::vector<uint8_t> BlockHeader::getPreviousHash() const { 
    return previousHash; 
}

std::string BlockHeader::getPreviousHashHex() const {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : previousHash) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::vector<uint8_t> BlockHeader::getMerkleRoot() const { 
    return merkleRoot; 
}

std::string BlockHeader::getMerkleRootHex() const {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : merkleRoot) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::time_t BlockHeader::getTimestamp() const { 
    return timestamp; 
}

std::vector<uint8_t> BlockHeader::getHash() const { 
    return hash; 
}

std::string BlockHeader::getHashHex() const {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : hash) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

// Setters
void BlockHeader::setMerkleRoot(const std::vector<uint8_t>& merkleRoot) {
    if (merkleRoot.size() != SHA256_HASH_SIZE) {
        throw std::invalid_argument("Invalid merkle root size");
    }
    this->merkleRoot = merkleRoot;
}

void BlockHeader::setHash(const std::vector<uint8_t>& hash) {
    if (hash.size() != SHA256_HASH_SIZE) {
        throw std::invalid_argument("Invalid hash size");
    }
    this->hash = hash;
}

// Validación
bool BlockHeader::isValid() const {
    return hasValidHashes() && isValidTimestamp();
}

bool BlockHeader::hasValidHashes() const {
    // previousHash válido
    if (index == 0) {
        // previousHash debe tener tamaño correcto
        if (previousHash.size() != SHA256_HASH_SIZE) return false;
        // Puede ser todo ceros
    } else {
        if (!isValidHash(previousHash)) return false;
    }

    // hash y merkleRoot siempre deben ser válidos y no todo ceros
    return isValidHash(merkleRoot) && isValidHash(hash);
}

bool BlockHeader::isValidHash(const std::vector<uint8_t>& hash) const {
    // Verificar tamaño correcto
    if (hash.size() != SHA256_HASH_SIZE) {
        return false;
    }

    // Verificar que no sea todo ceros
    if (std::all_of(hash.begin(), hash.end(), [](uint8_t b) { return b == 0; })) {
        return false;
    }

    return true;
}

bool BlockHeader::isValidTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto current_time = std::chrono::system_clock::to_time_t(now);
    
    // El timestamp no puede estar en el futuro (con margen de 2 minutos)
    if (timestamp > current_time + 120) {
        return false;
    }
    
    // El timestamp no puede ser demasiado antiguo (más de 1 año)
    if (timestamp < current_time - (365 * 24 * 60 * 60)) {
        return false;
    }
    
    return true;
}

std::string BlockHeader::toString() const {
    std::stringstream ss;
    ss << "BlockHeader{"
       << "index: " << index
       << ", previousHash: " << getPreviousHashHex()
       << ", merkleRoot: " << getMerkleRootHex()
       << ", timestamp: " << timestamp
       << ", hash: " << getHashHex()
       << "}";
    return ss.str();
}

std::vector<uint8_t> BlockHeader::toBytes() const {
    std::vector<uint8_t> bytes;
    
    // Serializar índice (8 bytes)
    for (int i = 0; i < 8; ++i) {
        bytes.push_back(static_cast<uint8_t>((index >> (i * 8)) & 0xFF));
    }
    
    // Serializar previousHash (32 bytes)
    bytes.insert(bytes.end(), previousHash.begin(), previousHash.end());
    
    // Serializar merkleRoot (32 bytes)
    bytes.insert(bytes.end(), merkleRoot.begin(), merkleRoot.end());
    
    // Serializar timestamp (8 bytes)
    int64_t timestamp64 = static_cast<int64_t>(timestamp);
    for (int i = 0; i < 8; ++i) {
        bytes.push_back(static_cast<uint8_t>((timestamp64 >> (i * 8)) & 0xFF));
    }
    
    return bytes;
}