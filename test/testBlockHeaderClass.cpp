#include <gtest/gtest.h>
#include "BlockHeader.hpp"
#include <limits>
#include <thread>
#include <chrono>

class BlockHeaderTest : public ::testing::Test {};

// ------------------- Constructor y getters básicos -------------------
TEST_F(BlockHeaderTest, ConstructorInitializesFields) {
    int64_t idx = 5;
    string prevHash = "abc123";
    BlockHeader header(idx, prevHash);

    EXPECT_EQ(header.getIndex(), idx);
    EXPECT_EQ(header.getPreviousHash(), prevHash);
    EXPECT_EQ(header.getMerkleRoot(), "");
    EXPECT_EQ(header.getHash(), "");
    EXPECT_LE(header.getTimestamp(), time(nullptr)); // timestamp <= ahora
}

// ------------------- Setters -------------------
TEST_F(BlockHeaderTest, SettersUpdateFields) {
    BlockHeader header(0, "prev");

    header.setMerkleRoot("merkle123");
    header.setHash("hash123");

    EXPECT_EQ(header.getMerkleRoot(), "merkle123");
    EXPECT_EQ(header.getHash(), "hash123");
}

// ------------------- toString -------------------
TEST_F(BlockHeaderTest, ToStringContainsAllFields) {
    BlockHeader header(2, "prevHash");
    header.setMerkleRoot("merkleRoot");
    string str = header.toString();

    EXPECT_NE(str.find("2"), string::npos);
    EXPECT_NE(str.find("prevHash"), string::npos);
    EXPECT_NE(str.find("merkleRoot"), string::npos);
    EXPECT_NE(str.find(to_string(header.getTimestamp())), string::npos);
}

// ------------------- Robustez / Opcionales -------------------

// Cambiar valores múltiples veces
TEST_F(BlockHeaderTest, MultipleSettersUpdates) {
    BlockHeader header(1, "prev");
    header.setMerkleRoot("root1");
    header.setHash("hash1");
    header.setMerkleRoot("root2");
    header.setHash("hash2");

    EXPECT_EQ(header.getMerkleRoot(), "root2");
    EXPECT_EQ(header.getHash(), "hash2");
}

// Timestamp siempre coherente
TEST_F(BlockHeaderTest, TimestampConsistency) {
    BlockHeader header(0, "prev");
    time_t t1 = header.getTimestamp();
    this_thread::sleep_for(chrono::milliseconds(10));
    time_t t2 = header.getTimestamp();

    EXPECT_EQ(t1, t2); // no cambia después de la creación
}

// Valores extremos para index y previousHash
TEST_F(BlockHeaderTest, ExtremeIndexAndPreviousHash) {
    int64_t maxIdx = numeric_limits<int64_t>::max();
    int64_t minIdx = numeric_limits<int64_t>::min();
    BlockHeader headerMax(maxIdx, "");
    BlockHeader headerMin(minIdx, "prev");

    EXPECT_EQ(headerMax.getIndex(), maxIdx);
    EXPECT_EQ(headerMax.getPreviousHash(), "");
    EXPECT_EQ(headerMin.getIndex(), minIdx);
    EXPECT_EQ(headerMin.getPreviousHash(), "prev");
}

// toString refleja cambios en setters
TEST_F(BlockHeaderTest, ToStringReflectsSetterChanges) {
    BlockHeader header(10, "prevHash");
    string initialStr = header.toString();

    header.setMerkleRoot("newRoot");
    header.setHash("newHash");

    string updatedStr = header.toString();
    EXPECT_NE(updatedStr, initialStr);
    EXPECT_NE(updatedStr.find("10"), string::npos);
    EXPECT_NE(updatedStr.find("prevHash"), string::npos);
    EXPECT_NE(updatedStr.find("newRoot"), string::npos);
}
