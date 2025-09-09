#ifndef BLOCKCHAIN_STORAGE_H
#define BLOCKCHAIN_STORAGE_H

#include "Block.hpp"
#include "Transaction.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <filesystem>

using namespace std;

class BlockchainStorage {
public:

    /**
     * The BlockchainStorage constructor initializes directories and file paths based on the provided data
     * directory.
     * 
     * @param dataDirectory The `dataDirectory` parameter is a reference to a `string` that represents the
     * directory where blockchain data will be stored.
     */
    BlockchainStorage(const string& dataDirectory = "blockchain_data");

    /**
     * The BlockchainStorage destructor clears the block and transaction caches.
     */
    ~BlockchainStorage();
    
    // ==== OPERACIONES BASICAS ====

    /**
     * The function `initialize` in the `BlockchainStorage` class initializes the blockchain storage by
     * ensuring directories exist and creating a chainstate file if it doesn't already exist.
     * 
     * @return The `initialize()` function returns a boolean value. It returns `true` if the initialization
     * is successful, and `false` if there is an error during initialization.
     */
    bool initialize();
    
    /**
     * The function `saveBlock` in the `BlockchainStorage` class saves a block to storage by serializing
     * it, writing it to a file, updating cache, and updating the latest block index.
     * 
     * @param block The `block` parameter in the `saveBlock` function represents a block of data in a
     * blockchain. It contains information such as the block header, transactions, and other relevant data
     * that needs to be stored in the blockchain. The function serializes this block, saves it to a file,
     * updates the
     * 
     * @return The `saveBlock` function returns a boolean value (`bool`). It returns `true` if the block
     * was successfully saved, and `false` if there was an error during the saving process.
     */
    bool saveBlock(const Block& block);
    
    /**
     * The function `loadBlock` in the `BlockchainStorage` class loads a block from storage, checking a
     * cache first and deserializing the block data if necessary.
     * 
     * @param index The `index` parameter in the `loadBlock` function represents the index of the block
     * that needs to be loaded from the blockchain storage. It is used to identify the specific block that
     * the function should retrieve and load into memory.
     * @param block The `block` parameter in the `loadBlock` function is a reference to a `Block` object.
     * This object will be populated with the data loaded from the blockchain storage at the specified
     * index.
     * 
     * @return A boolean value is being returned.
     */
    bool loadBlock(uint64_t index, Block& block);
    
    /**
     * The function `loadLastBlock` in the `BlockchainStorage` class loads the latest block from storage.
     * 
     * @param block The `block` parameter is a reference to a `Block` object. This function `loadLastBlock`
     * is a method of the `BlockchainStorage` class, and it is responsible for loading the latest block
     * from the blockchain storage into the provided `Block` object.
     * 
     * @return A boolean value is being returned.
     */
    bool loadLastBlock(Block& block);
    
    // ==== OPERACIONES DE CONSULTA ====

    /**
     * The function `getBlockCount` returns the number of block files in a directory while handling
     * exceptions.
     * 
     * @return The `getBlockCount` function returns the number of blocks present in the blockchain storage
     * directory. If an error occurs during the counting process, it catches the exception, prints an error
     * message with the exception details, and returns 0.
     */
    uint64_t getBlockCount() const;
    
    /**
     * The function `getLatestBlockIndex` retrieves the index of the latest block from a blockchain storage
     * directory.
     * 
     * @return The function `getLatestBlockIndex` returns the latest block index as a `uint64_t` data type.
     * If there is an error during the process, it returns `UINT64_MAX`.
     */
    uint64_t getLatestBlockIndex() const;
    
    /**
     * This function retrieves all block indexes from a directory of blockchain data files.
     * 
     * @return A vector of uint64_t containing all block indexes found in the specified directory.
     */
    vector<uint64_t> getAllBlockIndexes() const;  
    
    // ==== OPERACIONES DE TRANSACCIONES ====

    /**
     * The function `saveTransaction` in the `BlockchainStorage` class saves a transaction to a file and
     * caches it in memory, handling exceptions and returning a boolean indicating success.
     * 
     * @param transaction The `transaction` parameter is an object of type `Transaction`, which contains
     * information about a transaction to be saved in the blockchain storage.
     * 
     * @return The `saveTransaction` function returns a boolean value - `true` if the transaction was
     * successfully saved, and `false` if there was an error during the saving process.
     */
    bool saveTransaction(const Transaction& transaction); 
    
    /**
     * The function `loadTransaction` in the `BlockchainStorage` class loads a transaction from storage
     * using a transaction hash and caches it for future access.
     * 
     * @param txHash `txHash` is a string parameter representing the hash of a transaction that needs to be
     * loaded from the blockchain storage.
     * @param transaction The `transaction` parameter is a reference to a `Transaction` object. This
     * function `loadTransaction` is responsible for loading a transaction with a given transaction hash
     * from storage and populating the `transaction` object with the loaded data. If the transaction is
     * successfully loaded, the function returns `true`,
     * 
     * @return A boolean value is being returned.
     */
    bool loadTransaction(const string& txHash, Transaction& transaction); 
    
    /**
     * The function `getTransactionsByAddress` retrieves transactions associated with a specific address
     * from a blockchain storage directory.
     * 
     * @param address The `address` parameter in the `getTransactionsByAddress` function is a string that
     * represents the address for which you want to retrieve transactions from the blockchain storage. This
     * function iterates through the transactions stored in a directory, reads each transaction file,
     * deserializes it, and checks if the transaction
     * 
     * @return A vector of Transaction objects that involve the specified address is being returned.
     */
    vector<Transaction> getTransactionsByAddress(const string& address); 
    
    // ==== OPERACIONES DE CADENA ====

    /**
     * The function `saveChainState` saves the chain state data to a file in binary format, handling
     * exceptions and returning a boolean indicating success.
     * 
     * @param data The `data` parameter in the `saveChainState` function represents the information or
     * state of the blockchain that you want to save to a file. This data is passed as a `const string&`,
     * meaning it is a constant reference to a string, which helps in avoiding unnecessary copying of the
     * data
     * 
     * @return The `saveChainState` function returns a boolean value. It returns `true` if the chain state
     * data was successfully saved to the file, and `false` if there was an error during the saving
     * process.
     */
    bool saveChainState(const string& data);
    
    /**
     * The function `loadChainState` reads and returns the data stored in a file representing the state of
     * a blockchain, handling exceptions and locking access with a mutex.
     * 
     * @return The `loadChainState` function returns a string containing the data loaded from the chain
     * state file. If an error occurs during the loading process, an empty string is returned.
     */
    string loadChainState();
    
    // ==== UTILS ====
    
    /**
     * The function `clearStorage` clears the blockchain storage directory and ensures that necessary
     * directories exist.
     * 
     * @return The `clearStorage()` function returns a boolean value. If the storage is successfully
     * cleared and the directories are ensured to exist, it returns `true`. If an exception occurs during
     * the process, it catches the exception, prints an error message, and returns `false`.
     */
    bool clearStorage(); 
    
    /**
     * The `backup` function creates a backup of a blockchain storage directory at a specified path.
     * 
     * @param backupPath The `backupPath` parameter is a `const string&` type, which is a constant
     * reference to a string. It represents the path where the backup of the blockchain storage will be
     * created.
     * 
     * @return The `backup` function returns a boolean value. It returns `true` if the backup operation is
     * successful, and `false` if an error occurs during the backup process.
     */
    bool backup(const string& backupPath); 
    
    /**
     * The `restore` function in the `BlockchainStorage` class attempts to restore data from a backup file
     * to the data directory, handling exceptions and returning a boolean indicating success.
     * 
     * @param backupPath The `backupPath` parameter is a `const string&` type, which means it is a constant
     * reference to a string. It is used to specify the path to the backup file that contains the data to
     * be restored in the `BlockchainStorage::restore` method.
     * 
     * @return The `restore` function returns a boolean value. It returns `true` if the backup was
     * successfully restored, and `false` if there was an error during the restoration process.
     */
    bool restore(const string& backupPath); 
    
    // ==== VERIFICACION DE INTEGRIDAD
    
    /**
     * The function `verifyStorageIntegrity` in the `BlockchainStorage` class checks the integrity of
     * stored blocks by comparing their indexes and handles exceptions.
     * 
     * @return The `verifyStorageIntegrity` function returns a boolean value. It returns `true` if the
     * storage integrity is verified successfully without any issues, and it returns `false` if there are
     * any corrupted blocks, block index mismatches, or errors encountered during the verification process.
     */
    bool verifyStorageIntegrity(); 
    
private:
    string dataDir;
    string blocksDir;
    string transactionsDir;
    string chainStateFile;
    
    // ==== METODOS AUXILIARES ====

    /**
     * The function `ensureDirectoriesExist` creates necessary directories for blockchain storage and
     * returns true if successful, otherwise false.
     * 
     * @return The `ensureDirectoriesExist` function returns a boolean value. It returns `true` if the
     * directories are successfully created, and `false` if an exception occurs during the creation of
     * directories.
     */
    bool ensureDirectoriesExist();

    /**
     * The function `getBlockFilename` in the `BlockchainStorage` class generates a filename for a block
     * based on the block index.
     * 
     * @param index The `index` parameter in the `getBlockFilename` function represents the index of the
     * block for which you want to generate the filename.
     * 
     * @return The function `getBlockFilename` returns a string that represents the filename of a block in
     * the blockchain storage. The filename is constructed by concatenating the `blocksDir` path with
     * "/block_", the index padded with zeros to a width of 10 characters, and ".blk" extension.
     */
    string getBlockFilename(uint64_t index) const;
    
    /**
     * The function `getTransactionFilename` in the `BlockchainStorage` class returns the filename for a
     * transaction given its hash.
     * 
     * @param txHash The `txHash` parameter is a string representing the hash of a transaction.
     * 
     * @return The function `getTransactionFilename` returns a string that represents the file path for a
     * transaction file based on the provided transaction hash. The file path is constructed by
     * concatenating the `transactionsDir` directory path, the transaction hash `txHash`, and the file
     * extension ".tx".
     */
    string getTransactionFilename(const string& txHash) const; 
    
    // ==== SERIALIZACION ====
    
    /**
     * The function `serializeBlock` serializes a given `Block` object into a vector of `uint8_t` bytes.
     * 
     * @param block The `serializeBlock` function takes a `Block` object as a parameter and serializes its
     * data into a binary format. The `Block` object contains information such as header details (index,
     * timestamp, previous hash, merkle root, hash), and a list of transactions.
     * 
     * @return The `serializeBlock` function returns a `vector<uint8_t>` containing the serialized data of
     * a `Block` object. The function serializes various components of the block such as header
     * information, transactions, and their lengths, and then converts the serialized data into a
     * `vector<uint8_t>` before returning it.
     */
    vector<uint8_t> serializeBlock(const Block& block) const; // Revisar

    /**
     * The function `deserializeBlock` reads and deserializes data into a `Block` object in a blockchain
     * storage system.
     * 
     * @param data The `data` parameter in the `deserializeBlock` function is a vector of unsigned 8-bit
     * integers (`uint8_t`) that represents the serialized data of a block in a blockchain. This data needs
     * to be deserialized and converted back into a `Block` object.
     * @param block The `block` parameter in the `deserializeBlock` function is an output parameter of type
     * `Block`. This function is responsible for deserializing a vector of binary data into a `Block`
     * object and populating the `block` parameter with the deserialized data. The function returns a
     * boolean value
     * 
     * @return The function `deserializeBlock` returns a boolean value (`bool`). It returns `true` if the
     * deserialization process was successful and `false` if there was an error during deserialization.
     */    
    bool deserializeBlock(const vector<uint8_t>& data, Block& block) const; // Revisar
    
    /**
     * The function `serializeTransaction` serializes a `Transaction` object into a vector of uint8_t
     * bytes.
     * 
     * @param tx The `serializeTransaction` function takes a `Transaction` object `tx` as a parameter. This
     * `Transaction` object contains information such as the transaction hash, sender address, recipient
     * address, amount, timestamp, data, and signature.
     * 
     * @return The `serializeTransaction` function returns a `vector<uint8_t>` containing the
     * serialized data of a `Transaction` object. The data includes the hash, sender, recipient, amount,
     * timestamp, data, and signature of the transaction, all serialized into a binary format.
     */
    vector<uint8_t> serializeTransaction(const Transaction& transaction) const; 
    
    /**
     * The function `deserializeTransaction` deserializes transaction data from a vector of bytes into a
     * `Transaction` object.
     * 
     * @param data The `data` parameter is a vector of unsigned 8-bit integers, which represents the
     * serialized form of a transaction. This data needs to be deserialized in order to extract the
     * individual components of the transaction such as hash, sender, receiver, amount, data, timestamp,
     * and signature. The `
     * @param tx `tx` is an object of type `Transaction` which represents a transaction in a blockchain. It
     * likely has member functions like `setHash()`, `setFrom()`, `setTo()`, `setAmount()`, `setData()`,
     * `setTimestamp()`, and `setSignature()` to
     * 
     * @return The `deserializeTransaction` function returns a boolean value (`true` or `false`) indicating
     * whether the deserialization process was successful. If the deserialization was successful, it
     * returns `true`; otherwise, it returns `false`.
     */
    bool deserializeTransaction(const vector<uint8_t>& data, Transaction& transaction) const; 
    
    mutable unordered_map<uint64_t, Block> blockCache;
    mutable unordered_map<string, Transaction> transactionCache;
    
    mutable mutex storageMutex;
};

#endif // BLOCKCHAIN_STORAGE_H