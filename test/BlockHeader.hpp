#ifndef BLOCK_HEADER_H
#define BLOCK_HEADER_H

#include <string>
#include <vector>
#include <ctime>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include "Types.hpp"

class BlockHeader {
private:
    int64_t index;
    std::vector<uint8_t> previousHash;  // Hash binario del bloque anterior
    std::vector<uint8_t> merkleRoot;    // Raíz Merkle binaria
    std::time_t timestamp;
    std::vector<uint8_t> hash;          // Hash binario de este bloque

public:

    /**
     * Constructor del encabezado del bloque
     * 
     * @param index Índice del bloque en la blockchain
     * @param previousHash Hash del bloque anterior en formato binario
     */
    BlockHeader(int64_t index, const std::vector<uint8_t>& previousHash);
    
    // Getters
    int64_t getIndex() const;
    std::vector<uint8_t> getPreviousHash() const;
    std::string getPreviousHashHex() const;
    std::vector<uint8_t> getMerkleRoot() const;
    std::string getMerkleRootHex() const;
    std::time_t getTimestamp() const;
    std::vector<uint8_t> getHash() const;
    std::string getHashHex() const;
    
    // Setters limitados (solo para campos que pueden cambiar)
    void setMerkleRoot(const std::vector<uint8_t>& merkleRoot);
    void setHash(const std::vector<uint8_t>& hash);
    
    // Validación
    bool isValid() const;
    bool hasValidHashes() const;
    
    // Serialización
    std::string toString() const;
    std::vector<uint8_t> toBytes() const;

    // Helpers de validación
    bool isValidHash(const std::vector<uint8_t>& hash) const;
    bool isValidTimestamp() const;
};

#endif // BLOCK_HEADER_H