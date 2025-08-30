#include "BlockHeader.hpp"
#include <sstream>

BlockHeader::BlockHeader(int64_t index, const string& previousHash) : index(index), previousHash(previousHash) {
    timestamp = time(nullptr);
    hash = "";
    merkleRoot = "";
}

// Getters
int64_t BlockHeader::getIndex() const { return index; }
string BlockHeader::getPreviousHash() const { return previousHash; }
string BlockHeader::getMerkleRoot() const { return merkleRoot; }
time_t BlockHeader::getTimestamp() const { return timestamp; }
string BlockHeader::getHash() const { return hash; }

// Setters
void BlockHeader::setMerkleRoot(const string& merkleRoot) { this->merkleRoot = merkleRoot; }
void BlockHeader::setHash(const string& hash) { this->hash = hash; }

string BlockHeader::toString() const {
    stringstream ss;
    ss << index << previousHash << merkleRoot << timestamp;
    return ss.str();
}