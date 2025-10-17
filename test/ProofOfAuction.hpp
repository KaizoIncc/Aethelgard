#pragma once
#ifndef PROOF_OF_AUCTION_HPP
#define PROOF_OF_AUCTION_HPP

#include "Consensus.hpp"
#include <string>
#include <mutex>
#include <unordered_map>
#include <cstdint>

struct AuctionCommit {
    std::string commit_hex; // hex of commit hash
    uint64_t timestamp;
};

struct AuctionReveal {
    uint64_t bid;
    std::string nonce;
    uint64_t timestamp;
};

class ProofOfAuction : public Consensus {
public:
    ProofOfAuction();
    ~ProofOfAuction();

    bool validateBlock(const Block& b) override;
    void onNewBlock(const Block& b) override;

    // Auction API (in-memory simple implementation)
    bool submitCommit(const std::string& pubkey, const std::string& commitHex);
    bool submitReveal(const std::string& pubkey, uint64_t bid, const std::string& nonce);

    // Select winner after reveal phase (returns empty string if none)
    std::string selectWinner();

private:
    mutable std::mutex mtx_;
    std::unordered_map<std::string, AuctionCommit> commits_;
    std::unordered_map<std::string, AuctionReveal> reveals_;
};
#endif // PROOF_OF_AUCTION_HPP
