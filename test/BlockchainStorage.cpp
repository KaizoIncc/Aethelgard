#include "BlockchainStorage.hpp"

namespace fs = std::filesystem;

BlockchainStorage::BlockchainStorage(const std::string& dataDirectory) : dataDir(dataDirectory) {
    blocksDir = dataDir + "/blocks";
    transactionsDir = dataDir + "/transactions";
    chainStateFile = dataDir + "/chainstate.bin";
    indexFile = dataDir + "/block_index.bin"; // Nuevo archivo de índice
}

BlockchainStorage::~BlockchainStorage() {
    // Limpiar cache si es necesario
    blockCache.clear();
    transactionCache.clear();
}

// ==== IMPLEMENTACION DE TEMPLATES DE SERIALIZACION ====
template<typename T>
void BlockchainStorage::writeBinary(std::ostream& out, const T& value) const {
    out.write(reinterpret_cast<const char*>(&value), sizeof(T));
}

template<typename T>
void BlockchainStorage::readBinary(std::istream& in, T& value) const {
    in.read(reinterpret_cast<char*>(&value), sizeof(T));
}

void BlockchainStorage::writeVector(std::ostream& out, const std::vector<uint8_t>& data) const {
    uint64_t size = data.size();
    writeBinary(out, size);
    if (size > 0) {
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(size));
    }
}

std::vector<uint8_t> BlockchainStorage::readVector(std::istream& in) const {
    uint64_t size = 0;
    readBinary(in, size);
    
    if (size == 0) {
        return {};
    }
    
    if (size > 100 * 1024 * 1024) { // Límite de 100MB por seguridad
        throw std::runtime_error("Vector size too large: " + std::to_string(size));
    }
    
    std::vector<uint8_t> data(size);
    in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(size));
    return data;
}

void BlockchainStorage::writeString(std::ostream& out, const std::string& str) const {
    uint64_t size = str.size();
    writeBinary(out, size);
    if (size > 0) {
        out.write(str.data(), static_cast<std::streamsize>(size));
    }
}

std::string BlockchainStorage::readString(std::istream& in) const {
    uint64_t size = 0;
    readBinary(in, size);
    
    if (size == 0) {
        return "";
    }
    
    if (size > 10 * 1024 * 1024) { // Límite de 10MB por seguridad
        throw std::runtime_error("String size too large: " + std::to_string(size));
    }
    
    std::string str(size, '\0');
    in.read(&str[0], static_cast<std::streamsize>(size));
    return str;
}

bool BlockchainStorage::initialize() {
    std::lock_guard<std::recursive_mutex> lock(storageMutex);
    
    try {
        if (!ensureDirectoriesExist()) return false;
        
        // Crear archivo de chainstate si no existe
        if (!fs::exists(chainStateFile)) {
            std::ofstream stateFile(chainStateFile, std::ios::binary);
            if (!stateFile) return false;
            stateFile.close();
        }
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error initializing storage: " << e.what() << std::endl;
        return false;
    }
}

bool BlockchainStorage::ensureDirectoriesExist() {
    try {
        fs::create_directories(dataDir);
        fs::create_directories(blocksDir);
        fs::create_directories(transactionsDir);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error creating directories: " << e.what() << std::endl;
        return false;
    }
}

bool BlockchainStorage::saveBlock(const Block& block) {
    std::lock_guard<std::recursive_mutex> lock(storageMutex);
    
    try {
        uint64_t index = block.getHeader().getIndex();
        std::string filename = getBlockFilename(index);
        
        // Validar que el bloque sea válido antes de guardar
        if (!block.isValid()) {
            std::cerr << "Error: Cannot save invalid block" << std::endl;
            return false;
        }
        
        // Serializar bloque
        std::vector<uint8_t> serializedData = serializeBlock(block);
        if (serializedData.empty()) {
            std::cerr << "Error: Block serialization failed" << std::endl;
            return false;
        }
        
        // Validar tamaño serializado
        if (serializedData.size() > MAX_BLOCK_FILE_SIZE) {
            std::cerr << "Error: Serialized block exceeds maximum size" << std::endl;
            return false;
        }
        
        // Guardar en archivo
        std::ofstream file(filename, std::ios::binary);
        if (!file) {
            std::cerr << "Error: Cannot create block file: " << filename << std::endl;
            return false;
        }
        
        file.write(reinterpret_cast<const char*>(serializedData.data()), serializedData.size());
        file.close();
        
        if (!file.good()) {
            std::cerr << "Error: Failed to write block file" << std::endl;
            return false;
        }
        
        // Actualizar cache
        blockCache[index] = block;
        
        // Actualizar índice del último bloque
        if (!updateBlockIndex(index)) {
            std::cerr << "Warning: Failed to update block index" << std::endl;
            // No fallamos la operación principal por esto
        }
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error saving block: " << e.what() << std::endl;
        return false;
    }
}

bool BlockchainStorage::loadBlock(uint64_t index, Block& block, bool ignoreCache) {
    std::lock_guard<std::recursive_mutex> lock(storageMutex);

    if (!ignoreCache) {
        auto cacheIt = blockCache.find(index);
        if (cacheIt != blockCache.end()) {
            block = cacheIt->second;
            return true;
        }
    }

    std::string filename = getBlockFilename(index);
    if (!fs::exists(filename)) return false;

    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) return false;

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) return false;

    file.close();

    if (!deserializeBlock(buffer, block)) return false;

    // No actualizamos la cache si ignoreCache == true
    if (!ignoreCache) blockCache[index] = block;

    return true;
}

bool BlockchainStorage::loadLastBlock(Block& block) {
    uint64_t latestIndex = getLatestBlockIndex();
    if (latestIndex == UINT64_MAX) return false; // No hay bloques
    return loadBlock(latestIndex, block, false);
}

uint64_t BlockchainStorage::getBlockCount() const {
    std::lock_guard<std::recursive_mutex> lock(storageMutex);
    
    try {
        uint64_t count = 0;
        for (const auto& entry : fs::directory_iterator(blocksDir)) {
            if (entry.is_regular_file() && entry.path().extension() == ".blk") count++;
        }
        return count;
    } catch (const std::exception& e) {
        std::cerr << "Error counting blocks: " << e.what() << std::endl;
        return 0;
    }
}

uint64_t BlockchainStorage::getLatestBlockIndex() const {
    std::lock_guard<std::recursive_mutex> lock(storageMutex);
    
    try {
        std::string latestFile = blocksDir + "/latest.index";
        if (!fs::exists(latestFile)) return UINT64_MAX;
        
        std::ifstream file(latestFile, std::ios::binary);
        if (!file) return UINT64_MAX;
        
        uint64_t index;
        file.read(reinterpret_cast<char*>(&index), sizeof(index));
        file.close();
        
        return index;
    } catch (const std::exception& e) {
        std::cerr << "Error getting latest block index: " << e.what() << std::endl;
        return UINT64_MAX;
    }
}

std::string BlockchainStorage::getBlockFilename(uint64_t index) const {
    std::stringstream ss;
    ss << blocksDir << "/block_" << std::setw(10) << std::setfill('0') << index << ".blk";
    return ss.str();
}

// ==== OPERACIONES DE CHAINSTATE MEJORADAS ====
bool BlockchainStorage::saveChainState(const std::vector<uint8_t>& data) {
    std::lock_guard<std::recursive_mutex> lock(storageMutex);
    
    try {
        std::ofstream file(chainStateFile, std::ios::binary);
        if (!file) return false;
        
        // Escribir cabecera y checksum
        writeBinary(file, SERIALIZATION_VERSION);
        writeVector(file, data);
        
        uint32_t checksum = calculateChecksum(data);
        writeBinary(file, checksum);
        
        return file.good();
    } catch (const std::exception& e) {
        std::cerr << "Error saving chain state: " << e.what() << std::endl;
        return false;
    }
}

std::vector<uint8_t> BlockchainStorage::loadChainState() {
    std::lock_guard<std::recursive_mutex> lock(storageMutex);
    
    try {
        if (!fs::exists(chainStateFile)) {
            return {};
        }
        
        std::ifstream file(chainStateFile, std::ios::binary);
        if (!file) return {};
        
        uint32_t version;
        readBinary(file, version);
        
        if (version != SERIALIZATION_VERSION) {
            return {}; // Versión incompatible
        }
        
        std::vector<uint8_t> data = readVector(file);
        
        uint32_t storedChecksum;
        readBinary(file, storedChecksum);
        
        if (calculateChecksum(data) != storedChecksum) {
            return {}; // Datos corruptos
        }
        
        return data;
    } catch (const std::exception& e) {
        std::cerr << "Error loading chain state: " << e.what() << std::endl;
        return {};
    }
}

std::vector<uint64_t> BlockchainStorage::getAllBlockIndexes() const {
    std::lock_guard<std::recursive_mutex> lock(storageMutex);
    std::vector<uint64_t> indexes;

    try {
        for (const auto& entry : fs::directory_iterator(blocksDir)) {
            if (entry.is_regular_file() && entry.path().extension() == ".blk") {
                std::string fname = entry.path().stem().string(); // block_0000000001
                if (fname.rfind("block_", 0) == 0) {
                    std::string numStr = fname.substr(6);
                    try {
                        indexes.push_back(std::stoull(numStr));
                    } catch (...) {
                        continue;
                    }
                }
            }
        }
        std::sort(indexes.begin(), indexes.end());
    } catch (const std::exception& e) {
        std::cerr << "Error getting block indexes: " << e.what() << std::endl;
    }

    return indexes;
}

bool BlockchainStorage::saveTransaction(const Transaction& transaction) {
    std::lock_guard<std::recursive_mutex> lock(storageMutex);
    try {
        std::string txHash = transaction.getHashHex();
        std::string filename = getTransactionFilename(txHash);

        std::vector<uint8_t> serializedData = serializeTransaction(transaction);
        if (serializedData.empty()) return false;

        std::ofstream file(filename, std::ios::binary);
        if (!file) return false;

        file.write(reinterpret_cast<const char*>(serializedData.data()), serializedData.size());
        file.close();

        if (!file.good()) return false;

        transactionCache[txHash] = transaction;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error saving transaction: " << e.what() << std::endl;
        return false;
    }
}

bool BlockchainStorage::loadTransaction(const std::string& txHash, Transaction& transaction) {
    std::lock_guard<std::recursive_mutex> lock(storageMutex);
    try {
        auto it = transactionCache.find(txHash);
        if (it != transactionCache.end()) {
            transaction = it->second;
            return true;
        }

        std::string filename = getTransactionFilename(txHash);
        if (!fs::exists(filename)) return false;

        std::ifstream file(filename, std::ios::binary | std::ios::ate);
        if (!file) return false;

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<uint8_t> buffer(size);
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) return false;
        file.close();

        if (!deserializeTransaction(buffer, transaction)) return false;

        transactionCache[txHash] = transaction;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error loading transaction: " << e.what() << std::endl;
        return false;
    }
}

std::vector<Transaction> BlockchainStorage::getTransactionsByAddress(const std::string& address) {
    std::lock_guard<std::recursive_mutex> lock(storageMutex);
    std::vector<Transaction> result;

    try {
        for (const auto& entry : fs::directory_iterator(transactionsDir)) {
            if (entry.is_regular_file() && entry.path().extension() == ".tx") {
                std::ifstream file(entry.path(), std::ios::binary | std::ios::ate);
                if (!file) continue;

                std::streamsize size = file.tellg();
                file.seekg(0, std::ios::beg);

                std::vector<uint8_t> buffer(size);
                if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) continue;

                Transaction tx;
                if (!deserializeTransaction(buffer, tx)) continue;

                if (tx.involvesAddress(address)) result.push_back(tx);
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error getting transactions by address: " << e.what() << std::endl;
    }

    return result;
}

bool BlockchainStorage::clearStorage() {
    std::lock_guard<std::recursive_mutex> lock(storageMutex);
    try {
        fs::remove_all(dataDir);
        return ensureDirectoriesExist();
    } catch (const std::exception& e) {
        std::cerr << "Error clearing storage: " << e.what() << std::endl;
        return false;
    }
}

bool BlockchainStorage::backup(const std::string& backupPath) {
    std::lock_guard<std::recursive_mutex> lock(storageMutex);
    try {
        fs::remove_all(backupPath); // limpiar antes
        fs::create_directories(backupPath);
        fs::copy(dataDir, backupPath, fs::copy_options::recursive);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error creating backup: " << e.what() << std::endl;
        return false;
    }
}

bool BlockchainStorage::restore(const std::string& backupPath) {
    std::lock_guard<std::recursive_mutex> lock(storageMutex);
    try {
        if (!fs::exists(backupPath)) return false;
        fs::remove_all(dataDir);
        fs::copy(backupPath, dataDir, fs::copy_options::recursive);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error restoring backup: " << e.what() << std::endl;
        return false;
    }
}

bool BlockchainStorage::verifyStorageIntegrity() {
    std::lock_guard<std::recursive_mutex> lock(storageMutex);

    try {
        auto indexes = getAllBlockIndexes();
        if (indexes.empty()) {
            std::cout << "Info: No blocks found in storage" << std::endl;
            return true;
        }

        std::sort(indexes.begin(), indexes.end());
        uint64_t minIdx = indexes.front();
        uint64_t maxIdx = indexes.back();

        std::cout << "Verifying storage integrity from block " << minIdx << " to " << maxIdx << std::endl;

        std::unordered_set<uint64_t> existing(indexes.begin(), indexes.end());
        
        // Verificar secuencia continua
        for (uint64_t idx = minIdx; idx <= maxIdx; ++idx) {
            if (existing.find(idx) == existing.end()) {
                std::cerr << "Error: Missing block at index " << idx << std::endl;
                return false;
            }
            
            Block block;
            if (!loadBlock(idx, block, true)) {
                std::cerr << "Error: Corrupted block at index " << idx << std::endl;
                return false;
            }
            
            if (block.getHeader().getIndex() != idx) {
                std::cerr << "Error: Block index mismatch at " << idx << std::endl;
                return false;
            }
            
            if (!block.isValid()) {
                std::cerr << "Error: Invalid block at index " << idx << std::endl;
                return false;
            }
            
            // Verificar hash del bloque anterior (excepto para genesis)
            if (idx > minIdx) {
                Block prevBlock;
                if (loadBlock(idx - 1, prevBlock, true)) {
                    if (block.getHeader().getPreviousHash() != prevBlock.getHeader().getHash()) {
                        std::cerr << "Error: Block " << idx << " has incorrect previous hash" << std::endl;
                        return false;
                    }
                }
            }
        }
        
        std::cout << "Storage integrity verification completed successfully" << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error verifying storage: " << e.what() << std::endl;
        return false;
    }
}

std::string BlockchainStorage::getTransactionFilename(const std::string& txHash) const {
    return transactionsDir + "/" + txHash + ".tx";
}

// ==== SERIALIZACION DE TRANSACCIONES MEJORADA ====
std::vector<uint8_t> BlockchainStorage::serializeTransaction(const Transaction& tx) const {
    std::vector<uint8_t> result;
    
    // Usar stringstream en lugar de ostringstream para mejor control
    std::stringstream out(std::ios::binary | std::ios::out);
    
    // Cabecera de versión y magic number
    writeBinary(out, TX_MAGIC);
    writeBinary(out, SERIALIZATION_VERSION);
    
    // Escribir campos binarios directamente
    std::vector<uint8_t> hash = tx.getHash();
    writeVector(out, hash);
    
    writeString(out, tx.getFrom());
    writeString(out, tx.getTo());
    
    double amount = tx.getAmount();
    writeBinary(out, amount);
    
    writeString(out, tx.getData());
    
    int64_t timestamp = static_cast<int64_t>(tx.getTimestamp());
    writeBinary(out, timestamp);
    
    std::vector<uint8_t> signature = tx.getSignature();
    writeVector(out, signature);
    
    std::vector<uint8_t> publicKey = tx.getPublicKey();
    writeVector(out, publicKey);
    
    // Calcular checksum para integridad
    std::string serializedData = out.str();
    uint32_t checksum = calculateChecksum(serializedData);
    writeBinary(out, checksum);
    
    return std::vector<uint8_t>(serializedData.begin(), serializedData.end());
}

bool BlockchainStorage::deserializeTransaction(const std::vector<uint8_t>& data, Transaction& tx) const {
    if (data.empty()) {
        return false;
    }
    
    std::string blob(data.begin(), data.end());
    std::stringstream in(blob, std::ios::binary | std::ios::in);
    
    try {
        // Verificar magic number
        uint32_t magic;
        readBinary(in, magic);
        if (magic != TX_MAGIC) {
            return false;
        }
        
        // Verificar versión
        uint32_t version;
        readBinary(in, version);
        if (version != SERIALIZATION_VERSION) {
            return false; // Versión no compatible
        }
        
        // Leer campos
        std::vector<uint8_t> hash = readVector(in);
        std::string from = readString(in);
        std::string to = readString(in);
        
        double amount;
        readBinary(in, amount);
        
        std::string txData = readString(in);
        
        int64_t timestamp;
        readBinary(in, timestamp);
        
        std::vector<uint8_t> signature = readVector(in);
        std::vector<uint8_t> publicKey = readVector(in);
        
        // Verificar checksum
        uint32_t storedChecksum;
        readBinary(in, storedChecksum);
        
        // Recalcular checksum de los datos leídos
        std::string verifyData = blob.substr(0, blob.size() - sizeof(storedChecksum));
        uint32_t calculatedChecksum = calculateChecksum(verifyData);
        
        if (storedChecksum != calculatedChecksum) {
            return false; // Datos corruptos
        }
        
        // Reconstruir transacción usando constructor en lugar de setters
        Transaction temp(from, to, amount, txData);
        temp.setTimestamp(static_cast<time_t>(timestamp));
        temp.setHash(hash);
        temp.setSignature(signature);
        temp.setPublicKey(publicKey);
        
        tx = temp;
        
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Error deserializing transaction: " << e.what() << std::endl;
        return false;
    }
}

// ==== SERIALIZACION DE BLOQUES COMPATIBLE CON BlockHeader CORREGIDO ====
std::vector<uint8_t> BlockchainStorage::serializeBlock(const Block& block) const {
    std::stringstream out(std::ios::binary | std::ios::out);
    
    // Cabecera de serialización
    writeBinary(out, BLOCK_MAGIC);
    writeBinary(out, SERIALIZATION_VERSION);
    
    // Serializar header del bloque - COMPATIBLE CON VECTOR<UINT8_T>
    auto header = block.getHeader();
    writeBinary(out, header.getIndex());
    
    // Serializar hashes como vectores binarios
    std::vector<uint8_t> previousHash = header.getPreviousHash();
    writeVector(out, previousHash);
    
    std::vector<uint8_t> merkleRoot = header.getMerkleRoot();
    writeVector(out, merkleRoot);
    
    writeBinary(out, static_cast<int64_t>(header.getTimestamp()));
    
    std::vector<uint8_t> hash = header.getHash();
    writeVector(out, hash);
    
    // Serializar transacciones
    const auto transactions = block.getTransactions();
    uint64_t txCount = transactions.size();
    writeBinary(out, txCount);
    
    for (const auto& tx : transactions) {
        std::vector<uint8_t> txData = serializeTransaction(tx);
        writeVector(out, txData);
    }
    
    // Checksum final
    std::string serializedData = out.str();
    
    // Validar tamaño máximo
    if (serializedData.size() > MAX_BLOCK_FILE_SIZE) {
        throw std::runtime_error("Block serialization exceeds maximum size");
    }
    
    uint32_t checksum = calculateChecksum(serializedData);
    writeBinary(out, checksum);
    
    return std::vector<uint8_t>(serializedData.begin(), serializedData.end());
}

bool BlockchainStorage::deserializeBlock(const std::vector<uint8_t>& data, Block& block) const {
    if (data.empty()) {
        return false;
    }
    
    // Validar tamaño máximo
    if (data.size() > MAX_BLOCK_FILE_SIZE) {
        std::cerr << "Error: Block data exceeds maximum size" << std::endl;
        return false;
    }
    
    std::string blob(data.begin(), data.end());
    std::stringstream in(blob, std::ios::binary | std::ios::in);
    
    try {
        // Verificar magic number y versión
        uint32_t magic, version;
        readBinary(in, magic);
        readBinary(in, version);
        
        if (magic != BLOCK_MAGIC) {
            std::cerr << "Error: Invalid block magic number" << std::endl;
            return false;
        }
        
        if (version != SERIALIZATION_VERSION) {
            std::cerr << "Error: Unsupported block serialization version: " << version << std::endl;
            return false;
        }
        
        // Leer header - COMPATIBLE CON VECTOR<UINT8_T>
        uint64_t index;
        std::vector<uint8_t> previousHash, merkleRoot, hash;
        int64_t timestamp;
        
        readBinary(in, index);
        previousHash = readVector(in);
        merkleRoot = readVector(in);
        readBinary(in, timestamp);
        hash = readVector(in);
        
        if (!in.good()) {
            std::cerr << "Error: Failed to read block header" << std::endl;
            return false;
        }
        
        // Validar hashes
        if (previousHash.size() != SHA256_HASH_SIZE ||
            merkleRoot.size() != SHA256_HASH_SIZE ||
            hash.size() != SHA256_HASH_SIZE) {
            std::cerr << "Error: Invalid hash sizes in block deserialization" << std::endl;
            return false;
        }
        
        // Crear bloque con vectores binarios
        Block deserializedBlock(index, previousHash);
        
        // Leer transacciones
        uint64_t txCount;
        readBinary(in, txCount);
        
        // Validar número de transacciones
        if (txCount > MAX_TRANSACTIONS) {
            std::cerr << "Error: Block contains too many transactions: " << txCount << std::endl;
            return false;
        }
        
        for (uint64_t i = 0; i < txCount; ++i) {
            std::vector<uint8_t> txData = readVector(in);
            
            // Validar tamaño de transacción
            if (txData.size() > MAX_TX_FILE_SIZE) {
                std::cerr << "Error: Transaction data exceeds maximum size" << std::endl;
                return false;
            }
            
            Transaction tx;
            if (!deserializeTransaction(txData, tx)) {
                std::cerr << "Error: Failed to deserialize transaction " << i << std::endl;
                return false;
            }
            deserializedBlock.addTransaction(tx);
        }
        
        // Verificar checksum
        uint32_t storedChecksum;
        readBinary(in, storedChecksum);
        
        std::string verifyData = blob.substr(0, blob.size() - sizeof(storedChecksum));
        uint32_t calculatedChecksum = calculateChecksum(verifyData);
        
        if (storedChecksum != calculatedChecksum) {
            std::cerr << "Error: Block checksum verification failed" << std::endl;
            return false;
        }
        
        block = deserializedBlock;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Error deserializing block: " << e.what() << std::endl;
        return false;
    }
}

// ==== FUNCION AUXILIAR PARA CHECKSUM ====
uint32_t BlockchainStorage::calculateChecksum(const std::vector<uint8_t>& data) const {
    // Implementación simple de checksum - en producción usaría CRC32 o similar
    uint32_t checksum = 0;
    for (uint8_t byte : data) {
        checksum = (checksum << 5) + checksum + byte;
    }
    return checksum;
}

uint32_t BlockchainStorage::calculateChecksum(const std::string& data) const {
    return calculateChecksum(std::vector<uint8_t>(data.begin(), data.end()));
}

bool BlockchainStorage::updateBlockIndex(uint64_t latestIndex) {
    try {
        std::ofstream latest(blocksDir + "/latest.index", std::ios::binary);
        if (!latest) return false;
        
        latest.write(reinterpret_cast<const char*>(&latestIndex), sizeof(latestIndex));
        latest.close();
        
        return latest.good();
    } catch (const std::exception& e) {
        std::cerr << "Error updating block index: " << e.what() << std::endl;
        return false;
    }
}