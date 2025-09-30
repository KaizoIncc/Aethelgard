#ifndef BLOCK_HEADER_H
#define BLOCK_HEADER_H

#include <string>
#include <ctime>
#include <cstdint>
#include <sstream>

using namespace std;

class BlockHeader {
private:
    int64_t index;
    string previousHash;
    string merkleRoot;
    time_t timestamp;
    string hash;

public:

    /**
     * The BlockHeader constructor initializes the index, previous hash, timestamp, hash, and merkle root
     * of a block.
     * 
     * @param index The `index` parameter in the `BlockHeader` constructor is of type `int64_t` and
     * represents the index or position of the block in the blockchain.
     * @param previousHash The `previousHash` parameter in the `BlockHeader` constructor is a reference to
     * a `string` that represents the hash of the previous block in a blockchain. It is used to link the
     * current block to its predecessor in the chain.
     */
    BlockHeader(int64_t index, const string& previousHash);
    
    // Getters
    /**
     * The function `getIndex()` returns the index of a `BlockHeader` object.
     * 
     * @return The `index` member variable of the `BlockHeader` class is being returned as an `int64_t`
     * value.
     */
    int64_t getIndex() const;

    /**
     * This function returns the previous hash value stored in the BlockHeader object.
     * 
     * @return The `previousHash` string is being returned.
     */
    string getPreviousHash() const;
    
    /**
     * The function `getMerkleRoot` returns the Merkle root of a block header.
     * 
     * @return The `merkleRoot` string is being returned.
     */
    string getMerkleRoot() const;
    
    /**
     * This function returns the timestamp of a BlockHeader object.
     * 
     * @return The `timestamp` value of the `BlockHeader` object is being returned.
     */
    time_t getTimestamp() const;

    /**
     * The function `BlockHeader::getHash()` returns the hash value of a block header.
     * 
     * @return The `hash` value of the `BlockHeader` object is being returned.
     */
    string getHash() const;
    
    // Setters
    /**
     * The function `setMerkleRoot` sets the merkle root value for a BlockHeader object.
     * 
     * @param merkleRoot The `setMerkleRoot` function in the `BlockHeader` class is used to set the value
     * of the `merkleRoot` member variable to the provided `merkleRoot` string parameter. This function
     * allows you to update the merkle root value of a block header.
     */
    void setMerkleRoot(const string& merkleRoot);

    /**
     * The function `setHash` in the `BlockHeader` class sets the hash value to the provided string.
     * 
     * @param hash The `hash` parameter is a reference to a constant string that is being passed to the
     * `setHash` function in the `BlockHeader` class.
     */
    void setHash(const string& hash);
    
    /**
     * The `toString` function in the `BlockHeader` class converts the block header data into a string
     * format.
     * 
     * @return The `toString` function is returning a concatenated string of the `index`, `previousHash`,
     * `merkleRoot`, and `timestamp` member variables of the `BlockHeader` class.
     */
    string toString() const;
};

#endif // BLOCK_HEADER_H