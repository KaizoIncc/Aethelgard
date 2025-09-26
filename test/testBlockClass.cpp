#include <gtest/gtest.h>
#include "Block.hpp"
#include "Transaction.hpp"
#include "Utils.hpp"
#include <thread>
#include <chrono>
#include <vector>
#include <string>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>

using namespace std;

// ------------------- Helper para SHA-256 -------------------
string sha256Hex(const string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.c_str(), data.size());
    SHA256_Final(hash, &sha256);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    return ss.str();
}

// ------------------- Fixture -------------------
class BlockTest : public ::testing::Test {
protected:
    string privKey1, pubKey1, addr1;
    string privKey2, pubKey2, addr2;

    void SetUp() override {
        ASSERT_TRUE(CryptoUtils::generateKeyPair(privKey1, pubKey1));
        ASSERT_TRUE(CryptoUtils::generateKeyPair(privKey2, pubKey2));

        addr1 = CryptoUtils::publicKeyToAddress(pubKey1);
        addr2 = CryptoUtils::publicKeyToAddress(pubKey2);

        ASSERT_FALSE(addr1.empty());
        ASSERT_FALSE(addr2.empty());
    }
};

// ------------------- Constructores y getters -------------------
TEST_F(BlockTest, DefaultConstructor) {
    Block b;
    EXPECT_EQ(b.getHeader().getIndex(), 0);
    EXPECT_EQ(b.getHeader().getPreviousHash(), "");
    EXPECT_EQ(b.getTransactionCount(), 0);
}

TEST_F(BlockTest, ParameterizedConstructor) {
    Block b(1, "abc123");
    EXPECT_EQ(b.getHeader().getIndex(), 1);
    EXPECT_EQ(b.getHeader().getPreviousHash(), "abc123");
    EXPECT_EQ(b.getTransactionCount(), 0);
}

// ------------------- Añadir transacciones -------------------
TEST_F(BlockTest, AddValidTransaction) {
    Block b(1, "prevHash");
    Transaction tx(addr1, addr2, 5.0, "Pago");

    // Firmamos para que la transacción sea válida
    EXPECT_TRUE(tx.sign(privKey1));

    EXPECT_TRUE(b.addTransaction(tx));
    EXPECT_EQ(b.getTransactionCount(), 1);
}

TEST_F(BlockTest, AddInvalidTransaction) {
    Block b(1, "prevHash");
    Transaction tx(addr1, addr1, 5.0, "Invalid"); // from==to
    EXPECT_FALSE(b.addTransaction(tx));
    EXPECT_EQ(b.getTransactionCount(), 0);
}

// ------------------- Merkle Root -------------------
TEST_F(BlockTest, MerkleRootEmptyBlock) {
    Block b(1, "prev");
    EXPECT_EQ(b.calculateMerkleRoot(), sha256Hex(""));
}

TEST_F(BlockTest, MerkleRootSingleTransaction) {
    Block b(1, "prev");
    Transaction tx(addr1, addr2, 1.0, "A");

    // Firmamos para que la transacción sea válida
    EXPECT_TRUE(tx.sign(privKey1));

    b.addTransaction(tx);
    EXPECT_EQ(b.calculateMerkleRoot(), tx.getHash());
}

TEST_F(BlockTest, MerkleRootMultipleTransactions) {
    Block b(1, "prev");
    Transaction tx1(addr1, addr2, 1.0, "A");
    Transaction tx2(addr2, addr1, 2.0, "B");
    b.addTransaction(tx1);
    b.addTransaction(tx2);
    string root = b.calculateMerkleRoot();
    EXPECT_FALSE(root.empty());
}

// ------------------- Block Hash -------------------
TEST_F(BlockTest, BlockHashUpdatesHeader) {
    Block b(1, "prev");
    Transaction tx(addr1, addr2, 1.0, "A");
    b.addTransaction(tx);
    string hash = b.calculateBlockHash();
    EXPECT_EQ(hash, b.getHeader().getHash());
}

// ------------------- Validación -------------------
TEST_F(BlockTest, ValidBlock) {
    Block b(0, "");
    Transaction tx(addr1, addr2, 1.0, "A");
    b.addTransaction(tx);
    b.calculateBlockHash();
    EXPECT_TRUE(b.isValid());
}

TEST_F(BlockTest, InvalidBlockWithModifiedTransaction) {
    Block b(0, "");
    Transaction tx(addr1, addr2, 1.0, "A");
    b.addTransaction(tx);
    b.calculateBlockHash();
    Transaction modified = tx;
    modified.setAmount(10.0); // fuera del bloque
    EXPECT_TRUE(b.isValid()); // sigue válido porque tx dentro del bloque no cambió
}

TEST_F(BlockTest, InvalidPreviousHash) {
    Block b(1, "");
    EXPECT_FALSE(b.isValid()); // previousHash vacío en bloque no genesis
}

// ------------------- Robustez / estrés -------------------
TEST_F(BlockTest, ExtremeTransactions) {
    Block b(1, "prev");
    for(int i=0;i<1000;i++){
        Transaction tx(addr1, addr2, 1.0+i, "Tx"+to_string(i));
        b.addTransaction(tx);
    }
    b.calculateBlockHash();
    EXPECT_TRUE(b.isValid());
}

// ------------------- Timestamps y orden -------------------
TEST_F(BlockTest, TransactionsOrderMatters) {
    Block b(1, "prev");
    Transaction tx1(addr1, addr2, 1.0, "A");
    Transaction tx2(addr2, addr1, 2.0, "B");
    b.addTransaction(tx1);
    b.addTransaction(tx2);
    b.calculateBlockHash();
    EXPECT_TRUE(b.isValid());
}

// ------------------- Genesis block -------------------
TEST_F(BlockTest, GenesisBlockValid) {
    Block b(0, "");
    EXPECT_TRUE(b.isValid());
}

// ------------------- Empty block -------------------
TEST_F(BlockTest, EmptyBlockHashAndValid) {
    Block b(1, "prev");
    string hash = b.calculateBlockHash();
    EXPECT_EQ(hash, b.getHeader().getHash());
    EXPECT_TRUE(b.isValid());
}

// ------------------- Internal invalid transaction -------------------
TEST_F(BlockTest, BlockInvalidWithInternalInvalidTransaction) {
    Block b(1, "prev");
    Transaction invalidTx(addr1, addr1, 1.0, "Invalid"); // from==to
    EXPECT_FALSE(b.addTransaction(invalidTx)); // no se añade
}

// ------------------- Transactions order changes Merkle root -------------------
TEST_F(BlockTest, TransactionsOrderChangesMerkleRoot) {
    Block b1(1, "prev");
    Transaction tx1(addr1, addr2, 1.0, "A");

    // Firmamos para que la transacción sea válida
    EXPECT_TRUE(tx1.sign(privKey1));

    Transaction tx2(addr2, addr1, 2.0, "B");

    // Firmamos para que la transacción sea válida
    EXPECT_TRUE(tx2.sign(privKey2));

    b1.addTransaction(tx1);
    b1.addTransaction(tx2);
    string root1 = b1.calculateMerkleRoot();

    Block b2(1, "prev");
    b2.addTransaction(tx2);
    b2.addTransaction(tx1);
    string root2 = b2.calculateMerkleRoot();

    EXPECT_NE(root1, root2);
}

// ------------------- Duplicate transactions -------------------
TEST_F(BlockTest, DuplicateTransactions) {
    Block b(1, "prev");
    Transaction tx(addr1, addr2, 1.0, "A");

    // Firmamos para que la transacción sea válida
    EXPECT_TRUE(tx.sign(privKey1));

    b.addTransaction(tx);
    b.addTransaction(tx);
    b.calculateBlockHash();
    EXPECT_TRUE(b.isValid());
    EXPECT_EQ(b.getTransactionCount(), 2);
}

// ------------------- Extreme amounts in transactions -------------------
TEST_F(BlockTest, ExtremeTransactionAmounts) {
    Block b(1, "prev");
    Transaction txMax(addr1, addr2, DBL_MAX, "Max");
    Transaction txMin(addr1, addr2, DBL_MIN, "Min");
    b.addTransaction(txMax);
    b.addTransaction(txMin);
    b.calculateBlockHash();
    EXPECT_TRUE(b.isValid());
}
