#include "BlockchainStorage.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <unordered_set>

namespace fs = filesystem;

BlockchainStorage::BlockchainStorage(const string& dataDirectory) : dataDir(dataDirectory) {
    blocksDir = dataDir + "/blocks";
    transactionsDir = dataDir + "/transactions";
    chainStateFile = dataDir + "/chainstate.bin";
}

BlockchainStorage::~BlockchainStorage() {
    // Limpiar cache si es necesario
    blockCache.clear();
    transactionCache.clear();
}

// ===== Helpers binarios genéricos en memoria/archivo =====
/* The above code is template function `writeBinary` that writes the binary representation of a
given value to an output stream. It uses `reinterpret_cast` to interpret the value as a `char*` and
writes the bytes of the value to the output stream using the `write` function. The size of the value
is determined by `sizeof(T)`. */
template<typename T>
inline void writeBinary(ostream& out, const T& value) {
    out.write(reinterpret_cast<const char*>(&value), sizeof(T));
}

/* The above code is template function `readBinary` that reads binary data from an input stream
(`istream`) and stores it in a variable of type `T`. It uses the `read` function of the input stream
to read `sizeof(T)` bytes of data and stores it in the memory location pointed to by the address of
the variable `value` after casting it to a `char*`. This function is useful for reading binary data
directly into variables of different types. */
template<typename T>
inline void readBinary(istream& in, T& value) {
    in.read(reinterpret_cast<char*>(&value), sizeof(T));
}

/**
 * The `writeString` function writes a string to an output stream along with its length in binary
 * format.
 * 
 * @param out The `out` parameter is of type `ostream&`, which is a reference to an output stream. This
 * parameter is used to specify the output stream where the string data will be written.
 * @param str A constant reference to a string that contains the data to be written to the output
 * stream.
 */
inline void writeString(ostream& out, const string& str) {
    uint64_t len = static_cast<uint64_t>(str.size());
    writeBinary(out, len);
    if (len) out.write(str.data(), static_cast<streamsize>(len));
}

/**
 * The function `readString` reads a string from an input stream by first reading the length of the
 * string and then reading the characters into the string.
 * 
 * @param in The `in` parameter is an input stream (`istream`) from which the function will read data.
 * @param str `str` is a reference to a `string` object where the read string will be stored after
 * reading it from the input stream `in`.
 */
inline void readString(istream& in, string& str) {
    uint64_t len = 0;
    readBinary(in, len);
    str.resize(static_cast<size_t>(len));
    if (len) in.read(&str[0], static_cast<streamsize>(len));
}

bool BlockchainStorage::initialize() {
    lock_guard<recursive_mutex> lock(storageMutex);
    
    try {
        if (!ensureDirectoriesExist()) return false;
        
        // Crear archivo de chainstate si no existe
        if (!fs::exists(chainStateFile)) {
            ofstream stateFile(chainStateFile, ios::binary);
            if (!stateFile) return false;
            stateFile.close();
        }
        
        return true;
    } catch (const exception& e) {
        cerr << "Error initializing storage: " << e.what() << endl;
        return false;
    }
}

bool BlockchainStorage::ensureDirectoriesExist() {
    try {
        fs::create_directories(dataDir);
        fs::create_directories(blocksDir);
        fs::create_directories(transactionsDir);
        return true;
    } catch (const exception& e) {
        cerr << "Error creating directories: " << e.what() << endl;
        return false;
    }
}

bool BlockchainStorage::saveBlock(const Block& block) {
    lock_guard<recursive_mutex> lock(storageMutex);
    
    try {
        uint64_t index = block.getHeader().getIndex();
        string filename = getBlockFilename(index);
        
        // Serializar bloque
        vector<uint8_t> serializedData = serializeBlock(block);
        if (serializedData.empty()) return false;
        
        // Guardar en archivo
        ofstream file(filename, ios::binary);
        if (!file) return false;
        
        file.write(reinterpret_cast<const char*>(serializedData.data()), serializedData.size());
        file.close();
        
        if (!file.good()) return false;
        
        // Actualizar cache
        blockCache[index] = block;
        
        // Actualizar último bloque
        ofstream latest(blocksDir + "/latest.index", ios::binary);
        latest.write(reinterpret_cast<const char*>(&index), sizeof(index));
        latest.close();
        
        return true;
    } catch (const exception& e) {
        cerr << "Error saving block: " << e.what() << endl;
        return false;
    }
}

bool BlockchainStorage::loadBlock(uint64_t index, Block& block, bool ignoreCache) {
    lock_guard<recursive_mutex> lock(storageMutex);

    if (!ignoreCache) {
        auto cacheIt = blockCache.find(index);
        if (cacheIt != blockCache.end()) {
            block = cacheIt->second;
            return true;
        }
    }

    string filename = getBlockFilename(index);
    if (!fs::exists(filename)) return false;

    ifstream file(filename, ios::binary | ios::ate);
    if (!file) return false;

    streamsize size = file.tellg();
    file.seekg(0, ios::beg);

    vector<uint8_t> buffer(size);
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
    lock_guard<recursive_mutex> lock(storageMutex);
    
    try {
        uint64_t count = 0;
        for (const auto& entry : fs::directory_iterator(blocksDir)) {
            if (entry.is_regular_file() && entry.path().extension() == ".blk") count++;
        }
        return count;
    } catch (const exception& e) {
        cerr << "Error counting blocks: " << e.what() << endl;
        return 0;
    }
}

uint64_t BlockchainStorage::getLatestBlockIndex() const {
    lock_guard<recursive_mutex> lock(storageMutex);
    
    try {
        string latestFile = blocksDir + "/latest.index";
        if (!fs::exists(latestFile)) return UINT64_MAX;
        
        ifstream file(latestFile, ios::binary);
        if (!file) return UINT64_MAX;
        
        uint64_t index;
        file.read(reinterpret_cast<char*>(&index), sizeof(index));
        file.close();
        
        return index;
    } catch (const exception& e) {
        cerr << "Error getting latest block index: " << e.what() << endl;
        return UINT64_MAX;
    }
}

string BlockchainStorage::getBlockFilename(uint64_t index) const {
    stringstream ss;
    ss << blocksDir << "/block_" << setw(10) << setfill('0') << index << ".blk";
    return ss.str();
}

bool BlockchainStorage::saveChainState(const string& data) {
    lock_guard<recursive_mutex> lock(storageMutex);
    
    try {
        ofstream file(chainStateFile, ios::binary);
        if (!file) return false;
        
        file.write(data.c_str(), data.size());
        file.close();
        
        return file.good();
    } catch (const exception& e) {
        cerr << "Error saving chain state: " << e.what() << endl;
        return false;
    }
}

string BlockchainStorage::loadChainState() {
    lock_guard<recursive_mutex> lock(storageMutex);
    
    try {
        if (!fs::exists(chainStateFile)) return "";
        
        ifstream file(chainStateFile, ios::binary | ios::ate);
        if (!file) return "";
        
        streamsize size = file.tellg();
        file.seekg(0, ios::beg);
        
        string data(size, '\0');
        if (!file.read(&data[0], size)) return "";
        
        return data;
    } catch (const exception& e) {
        cerr << "Error loading chain state: " << e.what() << endl;
        return "";
    }
}

vector<uint64_t> BlockchainStorage::getAllBlockIndexes() const {
    lock_guard<recursive_mutex> lock(storageMutex);
    vector<uint64_t> indexes;

    try {
        for (const auto& entry : fs::directory_iterator(blocksDir)) {
            if (entry.is_regular_file() && entry.path().extension() == ".blk") {
                string fname = entry.path().stem().string(); // block_0000000001
                if (fname.rfind("block_", 0) == 0) {
                    string numStr = fname.substr(6);
                    try {
                        indexes.push_back(stoull(numStr));
                    } catch (...) {
                        continue;
                    }
                }
            }
        }
        sort(indexes.begin(), indexes.end());
    } catch (const exception& e) {
        cerr << "Error getting block indexes: " << e.what() << endl;
    }

    return indexes;
}

bool BlockchainStorage::saveTransaction(const Transaction& transaction) {
    lock_guard<recursive_mutex> lock(storageMutex);
    try {
        string txHash = transaction.getHash();
        string filename = getTransactionFilename(txHash);

        vector<uint8_t> serializedData = serializeTransaction(transaction);
        if (serializedData.empty()) return false;

        ofstream file(filename, ios::binary);
        if (!file) return false;

        file.write(reinterpret_cast<const char*>(serializedData.data()), serializedData.size());
        file.close();

        if (!file.good()) return false;

        transactionCache[txHash] = transaction;
        return true;
    } catch (const exception& e) {
        cerr << "Error saving transaction: " << e.what() << endl;
        return false;
    }
}

bool BlockchainStorage::loadTransaction(const string& txHash, Transaction& transaction) {
    lock_guard<recursive_mutex> lock(storageMutex);
    try {
        auto it = transactionCache.find(txHash);
        if (it != transactionCache.end()) {
            transaction = it->second;
            return true;
        }

        string filename = getTransactionFilename(txHash);
        if (!fs::exists(filename)) return false;

        ifstream file(filename, ios::binary | ios::ate);
        if (!file) return false;

        streamsize size = file.tellg();
        file.seekg(0, ios::beg);

        vector<uint8_t> buffer(size);
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) return false;
        file.close();

        if (!deserializeTransaction(buffer, transaction)) return false;

        transactionCache[txHash] = transaction;
        return true;
    } catch (const exception& e) {
        cerr << "Error loading transaction: " << e.what() << endl;
        return false;
    }
}

vector<Transaction> BlockchainStorage::getTransactionsByAddress(const string& address) {
    lock_guard<recursive_mutex> lock(storageMutex);
    vector<Transaction> result;

    try {
        for (const auto& entry : fs::directory_iterator(transactionsDir)) {
            if (entry.is_regular_file() && entry.path().extension() == ".tx") {
                ifstream file(entry.path(), ios::binary | ios::ate);
                if (!file) continue;

                streamsize size = file.tellg();
                file.seekg(0, ios::beg);

                vector<uint8_t> buffer(size);
                if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) continue;

                Transaction tx;
                if (!deserializeTransaction(buffer, tx)) continue;

                if (tx.involvesAddress(address)) result.push_back(tx);
            }
        }
    } catch (const exception& e) {
        cerr << "Error getting transactions by address: " << e.what() << endl;
    }

    return result;
}

bool BlockchainStorage::clearStorage() {
    lock_guard<recursive_mutex> lock(storageMutex);
    try {
        fs::remove_all(dataDir);
        return ensureDirectoriesExist();
    } catch (const exception& e) {
        cerr << "Error clearing storage: " << e.what() << endl;
        return false;
    }
}

bool BlockchainStorage::backup(const string& backupPath) {
    lock_guard<recursive_mutex> lock(storageMutex);
    try {
        fs::remove_all(backupPath); // limpiar antes
        fs::create_directories(backupPath);
        fs::copy(dataDir, backupPath, fs::copy_options::recursive);
        return true;
    } catch (const exception& e) {
        cerr << "Error creating backup: " << e.what() << endl;
        return false;
    }
}

bool BlockchainStorage::restore(const string& backupPath) {
    lock_guard<recursive_mutex> lock(storageMutex);
    try {
        if (!fs::exists(backupPath)) return false;
        fs::remove_all(dataDir);
        fs::copy(backupPath, dataDir, fs::copy_options::recursive);
        return true;
    } catch (const exception& e) {
        cerr << "Error restoring backup: " << e.what() << endl;
        return false;
    }
}

bool BlockchainStorage::verifyStorageIntegrity() {
    lock_guard<recursive_mutex> lock(storageMutex);

    try {
        auto indexes = getAllBlockIndexes();
        if (indexes.empty()) return true;

        std::sort(indexes.begin(), indexes.end());
        uint64_t minIdx = indexes.front();
        uint64_t maxIdx = indexes.back();

        std::unordered_set<uint64_t> existing(indexes.begin(), indexes.end());
        for (uint64_t idx = minIdx; idx <= maxIdx; ++idx) {
            if (existing.find(idx) == existing.end()) {
                cerr << "Missing block at index " << idx << endl;
                return false;
            }
            Block block;
            if (!loadBlock(idx, block, true)) {
                cerr << "Corrupted block at index " << idx << endl;
                return false;
            }
            if (block.getHeader().getIndex() != idx) {
                cerr << "Block index mismatch at " << idx << endl;
                return false;
            }
        }
        return true;
    } catch (const exception& e) {
        cerr << "Error verifying storage: " << e.what() << endl;
        return false;
    }
}

string BlockchainStorage::getTransactionFilename(const string& txHash) const {
    return transactionsDir + "/" + txHash + ".tx";
}

vector<uint8_t> BlockchainStorage::serializeTransaction(const Transaction& tx) const {
    ostringstream out(ios::binary);

    writeString(out, tx.getHash());
    writeString(out, tx.getFrom());
    writeString(out, tx.getTo());

    // Para portabilidad, mejor guardar time_t como int64_t
    double amount = tx.getAmount();
    int64_t ts = static_cast<int64_t>(tx.getTimestamp());

    writeBinary(out, amount);
    writeString(out, tx.getData());
    writeBinary(out, ts);
    writeString(out, tx.getSignature());

    const string blob = out.str();
    return vector<uint8_t>(blob.begin(), blob.end());
}

bool BlockchainStorage::deserializeTransaction(const vector<uint8_t>& data, Transaction& tx) const {
    string blob(reinterpret_cast<const char*>(data.data()), data.size());
    istringstream in(blob, ios::binary);

    string hash, from, to, d, sig;
    double amount = 0.0;
    int64_t ts = 0;

    readString(in, hash);
    readString(in, from);
    readString(in, to);
    readBinary(in, amount);
    readString(in, d);
    readBinary(in, ts);
    readString(in, sig);

    if (!in.good() && !in.eof()) return false;

    tx.setHash(hash);
    tx.setFrom(from);
    tx.setTo(to);
    tx.setAmount(amount);
    tx.setData(d);
    tx.setTimestamp(static_cast<time_t>(ts));
    tx.setSignature(sig);
    return true;
}

vector<uint8_t> BlockchainStorage::serializeBlock(const Block& block) const {
    ostringstream out(ios::binary);

    auto header = block.getHeader();
    int64_t index = header.getIndex();
    int64_t ts = static_cast<int64_t>(header.getTimestamp());

    writeBinary(out, index);
    writeString(out, header.getPreviousHash());
    writeString(out, header.getMerkleRoot());
    writeBinary(out, ts);
    writeString(out, header.getHash());

    const auto txs = block.getTransactions();
    uint64_t count = static_cast<uint64_t>(txs.size());
    writeBinary(out, count);

    for (const auto& tx : txs) {
        vector<uint8_t> buf = serializeTransaction(tx);
        uint64_t len = static_cast<uint64_t>(buf.size());
        writeBinary(out, len);
        if (len) out.write(reinterpret_cast<const char*>(buf.data()), static_cast<streamsize>(len));
    }

    const string blob = out.str();
    return vector<uint8_t>(blob.begin(), blob.end());
}

bool BlockchainStorage::deserializeBlock(const vector<uint8_t>& data, Block& block) const {
    string blob(reinterpret_cast<const char*>(data.data()), data.size());
    istringstream in(blob, ios::binary);

    int64_t index = 0, ts = 0;
    string prevHash, merkleRoot, hash;

    readBinary(in, index);
    readString(in, prevHash);
    readString(in, merkleRoot);
    readBinary(in, ts);
    readString(in, hash);

    if (!in.good() && !in.eof()) return false;

    Block b(static_cast<int64_t>(index), prevHash);

    // Si necesitas forzar merkleRoot/timestamp/hash en el header del bloque,
    // añade setters al Block/BlockHeader y setéalos aquí.

    uint64_t txCount = 0;
    readBinary(in, txCount);

    for (uint64_t i = 0; i < txCount; ++i) {
        uint64_t len = 0;
        readBinary(in, len);
        vector<uint8_t> buf(len);
        if (len) in.read(reinterpret_cast<char*>(buf.data()), static_cast<streamsize>(len));
        if (!in.good() && !in.eof()) return false;

        Transaction tx;
        if (!deserializeTransaction(buf, tx)) return false;
        b.addTransaction(tx);
    }

    block = b;
    return true;
}
