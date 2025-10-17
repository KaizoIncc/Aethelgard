#include "ProofOfAuction.hpp"
#include <sodium.h>
#include <iostream>

ProofOfAuction::ProofOfAuction() {}
ProofOfAuction::~ProofOfAuction() {}

bool ProofOfAuction::validateBlock(const Block& b) {
    // Basic placeholder: real validation should check proposer eligibility, merkle root and tx validity
    (void)b;
    return true;
}

void ProofOfAuction::onNewBlock(const Block& b) {
    (void)b;
    // clear auction state for next round - placeholder
    std::lock_guard<std::mutex> lk(mtx_);
    commits_.clear();
    reveals_.clear();
}

bool ProofOfAuction::submitCommit(const std::string& pubkey, const std::string& commitHex) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (commits_.count(pubkey)) return false;
    commits_[pubkey] = AuctionCommit{commitHex, (uint64_t)time(nullptr)};
    return true;
}

bool ProofOfAuction::submitReveal(const std::string& pubkey, uint64_t bid, const std::string& nonce) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (!commits_.count(pubkey)) return false;
    // Verify commit: commit == sha256_hex(pubkey|bid|nonce)
    // compute hash
    std::string input = pubkey + "|" + std::to_string(bid) + "|" + nonce;
    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash, reinterpret_cast<const unsigned char*>(input.data()), input.size());
    // convert to hex
    std::string hex;
    hex.reserve(crypto_hash_sha256_BYTES * 2);
    const char *hexchars = "0123456789abcdef";
    for (size_t i = 0; i < crypto_hash_sha256_BYTES; ++i) {
        hex.push_back(hexchars[(hash[i] >> 4) & 0xF]);
        hex.push_back(hexchars[hash[i] & 0xF]);
    }
    auto it = commits_.find(pubkey);
    if (it == commits_.end()) return false;
    if (hex != it->second.commit_hex) {
        // commit mismatch
        return false;
    }
    reveals_[pubkey] = AuctionReveal{bid, nonce, (uint64_t)time(nullptr)};
    return true;
}

std::string ProofOfAuction::selectWinner() {
    std::lock_guard<std::mutex> lk(mtx_);
    uint64_t best = 0;
    std::string bestPub;
    for (auto &kv : reveals_) {
        if (kv.second.bid > best) {
            best = kv.second.bid;
            bestPub = kv.first;
        }
    }
    return bestPub;
}
