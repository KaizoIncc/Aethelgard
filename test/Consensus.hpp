#pragma once
#ifndef CONSENSUS_HPP
#define CONSENSUS_HPP

#include "Block.hpp"

class Consensus {
public:
    virtual ~Consensus() = default;
    virtual bool validateBlock(const Block& b) = 0;
    virtual void onNewBlock(const Block& b) = 0;
};

#endif // CONSENSUS_HPP
