#include "Block.hpp"

Block::Block() : header(0, std::vector<uint8_t>(SHA256_HASH_SIZE, 0)) {}

Block::Block(int64_t index, const std::vector<uint8_t>& previousHash) 
    : header(index, previousHash) {
    
    // Validación de parámetros
    if (index < 0) {
        throw std::invalid_argument("Block index cannot be negative");
    }
    
    // Inicializamos Merkle root vacío para un bloque recién creado
    header.setMerkleRoot(calculateMerkleRoot());

    // Calculamos el hash inicial del header
    header.setHash(calculateBlockHash());
}

bool Block::addTransaction(const Transaction& transaction) {
    if (!transaction.isValid()) {
        std::cerr << "Error: Cannot add invalid transaction to block" << std::endl;
        return false;
    }
    
    if (!hasSpaceForTransaction(transaction)) {
        std::cerr << "Error: Block has no space for additional transaction" << std::endl;
        return false;
    }
    
    transactions.push_back(transaction);
    
    // Recalcular Merkle root y hash del bloque
    updateBlockHash();
    
    return true;
}

std::vector<uint8_t> Block::calculateMerkleRoot() const {
    if (transactions.empty()) {
        // Hash de datos vacíos para bloques sin transacciones
        return calculateHash(std::vector<uint8_t>());
    }
    
    std::vector<std::vector<uint8_t>> hashes;
    for (const auto& tx : transactions) { 
        hashes.push_back(tx.getHash()); 
    }
    
    // Algoritmo simple de merkle tree
    while (hashes.size() > 1) {
        std::vector<std::vector<uint8_t>> newHashes;
        
        for (size_t i = 0; i < hashes.size(); i += 2) {
            std::vector<uint8_t> combined;
            
            if (i + 1 < hashes.size()) {
                // Combinar dos hashes
                combined.insert(combined.end(), hashes[i].begin(), hashes[i].end());
                combined.insert(combined.end(), hashes[i + 1].begin(), hashes[i + 1].end());
            } else {
                // Duplicar el último hash si el número es impar
                combined.insert(combined.end(), hashes[i].begin(), hashes[i].end());
                combined.insert(combined.end(), hashes[i].begin(), hashes[i].end());
            }
            
            newHashes.push_back(calculateHash(combined));
        }
        
        hashes = newHashes;
    }
    
    return hashes[0];
}

std::vector<uint8_t> Block::calculateBlockHash() {
    // Calcular merkle root primero
    std::vector<uint8_t> merkleRoot = calculateMerkleRoot();
    header.setMerkleRoot(merkleRoot);
    
    // Calcular hash del header serializado
    std::vector<uint8_t> headerBytes = header.toBytes();
    std::vector<uint8_t> blockHash = calculateHash(headerBytes);
    header.setHash(blockHash);
    
    return blockHash;
}

bool Block::isValid() const {
    // Verificar hash del header
    std::vector<uint8_t> headerBytes = header.toBytes();
    std::vector<uint8_t> calculatedHash = calculateHash(headerBytes);
    if (calculatedHash != header.getHash()) {
        std::cerr << "Error: Block header hash mismatch" << std::endl;
        return false;
    }
    
    // Verificar merkle root
    std::vector<uint8_t> calculatedMerkleRoot = calculateMerkleRoot();
    if (calculatedMerkleRoot != header.getMerkleRoot()) {
        std::cerr << "Error: Block merkle root mismatch" << std::endl;
        return false;
    }
    
    // Verificar transacciones
    for (const auto& tx : transactions) { 
        if (!tx.isValid()) {
            std::cerr << "Error: Block contains invalid transaction" << std::endl;
            return false; 
        }
    }
    
    // Verificar límites de tamaño
    if (transactions.size() > MAX_TRANSACTIONS) {
        std::cerr << "Error: Block exceeds maximum transaction count" << std::endl;
        return false;
    }
    
    if (getEstimatedSize() > MAX_BLOCK_SIZE) {
        std::cerr << "Error: Block exceeds maximum size" << std::endl;
        return false;
    }
    
    // Verificar que el previousHash sea válido (excepto para el genesis block)
    if (header.getIndex() > 0) {
        std::vector<uint8_t> previousHash = header.getPreviousHash();
        if (previousHash.empty() || 
            std::all_of(previousHash.begin(), previousHash.end(), [](uint8_t b) { return b == 0; })) {
            std::cerr << "Error: Invalid previous hash for non-genesis block" << std::endl;
            return false;
        }
    }
    
    return true;
}

// Getters
BlockHeader Block::getHeader() const { 
    return header; 
}

std::vector<Transaction> Block::getTransactions() const { 
    return transactions; 
}

int64_t Block::getTransactionCount() const { 
    return static_cast<int64_t>(transactions.size()); 
}

size_t Block::getEstimatedSize() const {
    // Estimación simple del tamaño del bloque
    size_t size = header.toBytes().size(); // Tamaño del header
    
    for (const auto& tx : transactions) {
        // Estimación del tamaño de transacción (hash + direcciones + amount + timestamp)
        size += 32 + 40 + 40 + 8 + 8 + 8; // Valores conservadores
    }
    
    return size;
}

// Setters para reconstrucción
void Block::setHeader(const BlockHeader& newHeader) {
    header = newHeader;
}

void Block::setTransactions(const std::vector<Transaction>& newTransactions) {
    transactions = newTransactions;
    updateBlockHash();
}

std::vector<uint8_t> Block::calculateHash(const std::vector<uint8_t>& data) const {
    std::vector<uint8_t> hash(crypto_hash_sha256_BYTES); // 32 bytes
    
    if (data.empty()) {
        // Hash de datos vacíos
        crypto_hash_sha256(hash.data(), nullptr, 0);
    } else {
        // Calcular hash SHA-256 con libsodium
        crypto_hash_sha256(hash.data(), data.data(), data.size());
    }
    
    return hash;
}

// Helpers privados
bool Block::hasSpaceForTransaction(const Transaction& transaction) const {
    // Verificar límite de transacciones
    if (transactions.size() >= MAX_TRANSACTIONS) {
        return false;
    }
    
    // Estimación conservadora del tamaño de la transacción
    size_t transactionSize = 200; // Estimación conservadora en bytes
    
    // Verificar límite de tamaño de bloque
    if (getEstimatedSize() + transactionSize > MAX_BLOCK_SIZE) {
        return false;
    }
    
    return true;
}

void Block::updateBlockHash() {
    calculateBlockHash();
}