#include "Block.hpp"
#include <iomanip>
#include <algorithm>

Block::Block() : header(0, "") {};

Block::Block(int64_t index, const string& previousHash) : header(index, previousHash) {}

bool Block::addTransaction(const Transaction& transaction) {
    if (!transaction.isValid()) return false;
    
    transactions.push_back(transaction);
    return true;
}


string Block::calculateMerkleRoot() const {
    if (transactions.empty()) return calculateHash(""); // Hash vacío para bloques sin transacciones
    
    vector<string> hashes;
    for (const auto& tx : transactions) { hashes.push_back(tx.getHash()); }
    
    // Algoritmo simple de merkle tree
    while (hashes.size() > 1) {
        vector<string> newHashes;
        
        for (size_t i = 0; i < hashes.size(); i += 2) {
            if (i + 1 < hashes.size()) newHashes.push_back(calculateHash(hashes[i] + hashes[i + 1]));
            else newHashes.push_back(calculateHash(hashes[i] + hashes[i]));
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
    for (const auto& tx : transactions) { if (!tx.isValid()) return false; }
    
    // Verificar que el previousHash no esté vacío (excepto para el genesis block)
    if (header.getIndex() > 0 && header.getPreviousHash().empty()) return false;
    
    return true;
}

BlockHeader Block::getHeader() const { return header; }
vector<Transaction> Block::getTransactions() const { return transactions; }
int64_t Block::getTransactionCount() const { return transactions.size(); }


string Block::calculateHash(const string& data) const {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.c_str(), data.size());
    SHA256_Final(hash, &sha256);
    
    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) { ss << hex << setw(2) << setfill('0') << (int)hash[i]; }
    
    return ss.str();
}