#include "Block.hpp"

Block::Block() : header(0, "") {};

Block::Block(int64_t index, const string& previousHash) : header(index, previousHash) {
    // Inicializamos Merkle root vacío para un bloque recién creado
    header.setMerkleRoot(calculateMerkleRoot());

    // Calculamos el hash inicial del header
    header.setHash(calculateHash(header.toString()));
}

bool Block::addTransaction(const Transaction& transaction) {
    if (!transaction.isValid()) return false;
    transactions.push_back(transaction);
    
    // Recalcular Merkle root y hash del bloque
    string merkle = calculateMerkleRoot();
    header.setMerkleRoot(merkle);
    string h = calculateHash(header.toString());
    header.setHash(h);
    
    return true;
}

string Block::calculateMerkleRoot() const {
    if (transactions.empty()) return calculateHash(""); // Hash vacío para bloques sin transacciones
    
    vector<string> hashes;
    for (const auto& tx : transactions) { 
        hashes.push_back(tx.getHash()); 
    }
    
    // Algoritmo simple de merkle tree
    while (hashes.size() > 1) {
        vector<string> newHashes;
        
        for (size_t i = 0; i < hashes.size(); i += 2) {
            if (i + 1 < hashes.size()) {
                newHashes.push_back(calculateHash(hashes[i] + hashes[i + 1]));
            } else {
                newHashes.push_back(calculateHash(hashes[i] + hashes[i]));
            }
        }
        
        hashes = newHashes;
    }
    
    return hashes[0];
}

string Block::calculateBlockHash() {
    // Calcular merkle root primero
    header.setMerkleRoot(calculateMerkleRoot());
    
    // Calcular hash del header
    string blockHash = calculateHash(header.toString());
    header.setHash(blockHash);
    
    return blockHash;
}

bool Block::isValid() const {
    // Verificar hash del header
    string calculatedHash = calculateHash(header.toString());
    if (calculatedHash != header.getHash()) return false;
    
    // Verificar merkle root
    if (calculateMerkleRoot() != header.getMerkleRoot()) return false;
    
    // Verificar transacciones
    for (const auto& tx : transactions) { 
        if (!tx.isValid()) return false; 
    }
    
    // Verificar que el previousHash no esté vacío (excepto para el genesis block)
    if (header.getIndex() > 0 && header.getPreviousHash().empty()) return false;
    
    return true;
}

BlockHeader Block::getHeader() const { return header; }
vector<Transaction> Block::getTransactions() const { return transactions; }
int64_t Block::getTransactionCount() const { return transactions.size(); }

string Block::calculateHash(const string& data) const {
    // ¡VERSIÓN ACTUALIZADA CON LIBSODIUM!
    vector<uint8_t> hash(crypto_hash_sha256_BYTES); // 32 bytes
    
    // Calcular hash SHA-256 con libsodium
    crypto_hash_sha256(hash.data(), 
                      reinterpret_cast<const unsigned char*>(data.c_str()), 
                      data.size());
    
    // Convertir a hexadecimal
    stringstream ss;
    for (uint8_t byte : hash) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(byte);
    }
    
    return ss.str();
}