#ifndef BLOCK_H
#define BLOCK_H

#include "BlockHeader.hpp"
#include "Transaction.hpp"
#include "Types.hpp"
#include <vector>
#include <memory>
#include <string>
#include <sodium.h>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>

class Block {
private:
    BlockHeader header;
    std::vector<Transaction> transactions;

    /**
     * Calcula el hash SHA-256 de datos binarios
     */
    std::vector<uint8_t> calculateHash(const std::vector<uint8_t>& data) const;

public:

    /**
     * Constructor por defecto
     */
    Block();

    /**
     * Constructor principal
     * 
     * @param index Índice del bloque en la blockchain
     * @param previousHash Hash del bloque anterior en formato binario
     */
    Block(int64_t index, const std::vector<uint8_t>& previousHash);
    
    /**
     * Añade una transacción al bloque si es válida y hay espacio
     */
    bool addTransaction(const Transaction& transaction);

    /**
     * Calcula la raíz Merkle de las transacciones
     */
    std::vector<uint8_t> calculateMerkleRoot() const;
    
    /**
     * Calcula el hash del bloque completo
     */
    std::vector<uint8_t> calculateBlockHash();
    
    /**
     * Verifica la validez del bloque
     */
    bool isValid() const;
    
    // Getters
    BlockHeader getHeader() const;
    std::vector<Transaction> getTransactions() const;
    int64_t getTransactionCount() const;
    size_t getEstimatedSize() const;

    // Setters para reconstrucción
    void setHeader(const BlockHeader& newHeader);
    void setTransactions(const std::vector<Transaction>& newTransactions);

    // Helpers internos
    bool hasSpaceForTransaction(const Transaction& transaction) const;
    void updateBlockHash();
};

#endif // BLOCK_H