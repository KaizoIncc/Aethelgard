#ifndef BLOCK_H
#define BLOCK_H

#include "BlockHeader.hpp"
#include "Transaction.hpp"
#include <sodium.h>
#include <memory>
#include <iomanip>
#include <algorithm>

using namespace std;

class Block {
private:
    BlockHeader header;
    vector<Transaction> transactions;
    
    /**
     * The `calculateHash` function calculates the SHA-256 hash of the input data and returns it as
     * a hexadecimal string.
     * 
     * @param data The `data` parameter in the `calculateHash` function is a constant reference to a string
     * that represents the data for which you want to calculate the hash. This data will be used as input
     * to the SHA-256 hashing algorithm to generate a hash value.
     * 
     * @return The `calculateHash` function returns a string that represents the SHA-256 hash of the input
     * data provided as a parameter.
     */
    string calculateHash(const string& data) const;

public:
    /**
     * The Block constructor initializes the header with default values.
     */
    Block();

    /**
     * The Block constructor initializes a Block object with the given index and previous hash.
     * 
     * @param index The `index` parameter in the `Block` constructor is of type `int64_t` and represents
     * the position of the block within the blockchain. It is a unique identifier for each block in the
     * chain.
     * @param previousHash The `previousHash` parameter in the `Block` constructor is a reference to a
     * `string` representing the hash of the previous block in the blockchain. This hash is used to
     * maintain the integrity and immutability of the blockchain by linking each block to its predecessor.
     */
    Block(int64_t index, const string& previousHash);
    
    /**
     * The function `addTransaction` in the `Block` class adds a transaction to the block if it is valid.
     * 
     * @param transaction The `addTransaction` method in the `Block` class takes a `Transaction` object as
     * a parameter. The method first checks if the transaction is valid using the `isValid` method of the
     * `Transaction` class. If the transaction is valid, it is added to the `transactions` vector in
     * 
     * @return The `addTransaction` method returns a boolean value - `true` if the transaction was
     * successfully added to the `transactions` vector, and `false` if the transaction is not valid and was
     * not added.
     */
    bool addTransaction(const Transaction& transaction);
    
    /**
     * The function `calculateMerkleRoot` calculates the Merkle root hash for a block's transactions using
     * a simple Merkle tree algorithm.
     * 
     * @return The `calculateMerkleRoot` function returns the Merkle root hash of the block's transactions.
     */
    string calculateMerkleRoot() const;
    
    /**
     * The function `calculateBlockHash` calculates the hash of a block by first calculating the Merkle
     * root and then hashing the block header.
     * 
     * @return The `calculateBlockHash` function is returning a string representing the hash of the block
     * header after setting the Merkle root and calculating the hash of the header.
     */
    string calculateBlockHash();
    
    /**
     * The `isValid` function checks the validity of a block by verifying the hash of the header,
     * the Merkle root, individual transactions, and the previous hash.
     * 
     * @return The `isValid()` function is returning a boolean value. It returns `true` if the block is
     * considered valid based on the conditions checked within the function, and `false` if any of the
     * conditions fail.
     */
    bool isValid() const;
    
    // Getters
    /**
     * The function `getHeader` returns the header of a `Block` object.
     * 
     * @return The `header` member variable of the `Block` class is being returned.
     */
    BlockHeader getHeader() const;

    /**
     * This function returns a vector of Transaction objects stored in a Block.
     * 
     * @return A vector of Transaction objects is being returned.
     */
    vector<Transaction> getTransactions() const;

    /**
     * This function returns the number of transactions in a block.
     * 
     * @return The function `getTransactionCount` is returning the number of transactions in the
     * `transactions` vector, which is of type `int64_t`.
     */
    int64_t getTransactionCount() const;
};

#endif // BLOCK_H