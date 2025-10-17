#ifndef BLOCKCHAIN_STORAGE_H
#define BLOCKCHAIN_STORAGE_H

#include "Block.hpp"
#include "Transaction.hpp"
#include "Types.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <filesystem>
#include <mutex>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <unordered_set>
#include <cstdint>

class BlockchainStorage {
public:

    BlockchainStorage(const std::string& dataDirectory = "blockchain_data");
    ~BlockchainStorage();
    
    // ==== OPERACIONES BASICAS ====
    bool initialize();
    bool saveBlock(const Block& block);
    bool loadBlock(uint64_t index, Block& block, bool ignoreCache);
    bool loadLastBlock(Block& block);
    
    // ==== OPERACIONES DE CONSULTA ====
    uint64_t getBlockCount() const;
    uint64_t getLatestBlockIndex() const;
    std::vector<uint64_t> getAllBlockIndexes() const;  
    
    // ==== OPERACIONES DE TRANSACCIONES ====
    bool saveTransaction(const Transaction& transaction); 
    bool loadTransaction(const std::string& txHash, Transaction& transaction); 
    std::vector<Transaction> getTransactionsByAddress(const std::string& address); 
    
    // ==== OPERACIONES DE CADENA ====
    bool saveChainState(const std::vector<uint8_t>& data);
    std::vector<uint8_t> loadChainState();
    
    // ==== UTILS ====
    bool clearStorage(); 
    bool backup(const std::string& backupPath); 
    bool restore(const std::string& backupPath); 
    
    // ==== VERIFICACION DE INTEGRIDAD ====
    bool verifyStorageIntegrity(); 
    
    // ==== OPTIMIZACIONES FUTURAS ====
    bool compactStorage(); // Para futura implementación con base de datos
    
private:
    std::string dataDir;
    std::string blocksDir;
    std::string transactionsDir;
    std::string chainStateFile;
    std::string indexFile; // Archivo de índice para mejor escalabilidad
    
    // ==== METODOS AUXILIARES ====
    bool ensureDirectoriesExist();
    std::string getBlockFilename(uint64_t index) const;
    std::string getTransactionFilename(const std::string& txHash) const;
    bool updateBlockIndex(uint64_t latestIndex);
    
    // ==== FUNCION AUXILIAR PARA CHECKSUM ====
    uint32_t calculateChecksum(const std::vector<uint8_t>& data) const;
    uint32_t calculateChecksum(const std::string& data) const;

    // ==== SERIALIZACION MEJORADA Y COMPATIBLE ====
    std::vector<uint8_t> serializeBlock(const Block& block) const;
    bool deserializeBlock(const std::vector<uint8_t>& data, Block& block) const;
    
    std::vector<uint8_t> serializeTransaction(const Transaction& transaction) const; 
    bool deserializeTransaction(const std::vector<uint8_t>& data, Transaction& transaction) const;
    
    // ==== HELPERS DE SERIALIZACION SEGURA ====
    template<typename T>
    void writeBinary(std::ostream& out, const T& value) const;
    
    template<typename T>
    void readBinary(std::istream& in, T& value) const;
    
    void writeVector(std::ostream& out, const std::vector<uint8_t>& data) const;
    std::vector<uint8_t> readVector(std::istream& in) const;
    
    void writeString(std::ostream& out, const std::string& str) const;
    std::string readString(std::istream& in) const;
    
    // ==== CACHE Y SINCRONIZACION ====
    mutable std::unordered_map<uint64_t, Block> blockCache;
    mutable std::unordered_map<std::string, Transaction> transactionCache;
    mutable std::recursive_mutex storageMutex;
};

#endif // BLOCKCHAIN_STORAGE_H