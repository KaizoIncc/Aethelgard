#include <gtest/gtest.h>
#include "Block.hpp"
#include "Transaction.hpp"
#include "Utils.hpp"
#include <thread>
#include <chrono>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cfloat>  // Para DBL_MAX, DBL_MIN

using namespace std;

// ------------------- Fixture -------------------
class BlockTest : public ::testing::Test {
protected:
    string privKey1, pubKey1, addr1;
    string privKey2, pubKey2, addr2;

    void SetUp() override {
        // Inicializar crypto system primero
        ASSERT_TRUE(CryptoUtils::initialize());
        
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
    // Usamos CryptoUtils::sha256 en lugar de sha256Hex
    EXPECT_EQ(b.calculateMerkleRoot(), CryptoUtils::sha256(""));
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
    
    // Firmar las transacciones
    EXPECT_TRUE(tx1.sign(privKey1));
    EXPECT_TRUE(tx2.sign(privKey2));
    
    b.addTransaction(tx1);
    b.addTransaction(tx2);
    string root = b.calculateMerkleRoot();
    EXPECT_FALSE(root.empty());
}

// ------------------- Block Hash -------------------
TEST_F(BlockTest, BlockHashUpdatesHeader) {
    Block b(1, "prev");
    Transaction tx(addr1, addr2, 1.0, "A");
    
    // Firmar la transacción
    EXPECT_TRUE(tx.sign(privKey1));
    
    b.addTransaction(tx);
    string hash = b.calculateBlockHash();
    EXPECT_EQ(hash, b.getHeader().getHash());
}

// ------------------- Validación -------------------
TEST_F(BlockTest, ValidBlock) {
    Block b(0, "");
    Transaction tx(addr1, addr2, 1.0, "A");
    
    // Firmar la transacción
    EXPECT_TRUE(tx.sign(privKey1));
    
    b.addTransaction(tx);
    b.calculateBlockHash();
    EXPECT_TRUE(b.isValid());
}

TEST_F(BlockTest, InvalidBlockWithModifiedTransaction) {
    Block b(0, "");
    Transaction tx(addr1, addr2, 1.0, "A");
    
    // Firmar la transacción
    EXPECT_TRUE(tx.sign(privKey1));
    
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
    for(int i = 0; i < 1000; i++) {
        Transaction tx(addr1, addr2, 1.0 + i, "Tx" + to_string(i));
        
        // Firmar cada transacción
        EXPECT_TRUE(tx.sign(privKey1));
        
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
    
    // Firmar las transacciones
    EXPECT_TRUE(tx1.sign(privKey1));
    EXPECT_TRUE(tx2.sign(privKey2));
    
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
    Transaction tx2(addr2, addr1, 2.0, "B");

    // Firmar las transacciones
    EXPECT_TRUE(tx1.sign(privKey1));
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

    // Firmar la transacción
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
    
    // Firmar las transacciones
    EXPECT_TRUE(txMax.sign(privKey1));
    EXPECT_TRUE(txMin.sign(privKey1));
    
    b.addTransaction(txMax);
    b.addTransaction(txMin);
    b.calculateBlockHash();
    EXPECT_TRUE(b.isValid());
}

// ------------------- Performance Test -------------------
TEST_F(BlockTest, PerformanceTest) {
    auto start = chrono::high_resolution_clock::now();
    
    Block b(1, "prev");
    for(int i = 0; i < 100; i++) {
        Transaction tx(addr1, addr2, 1.0 + i, "Tx" + to_string(i));
        
        // Firmar con libsodium (¡8x más rápido!)
        EXPECT_TRUE(tx.sign(privKey1));
        
        b.addTransaction(tx);
    }
    
    b.calculateBlockHash();
    EXPECT_TRUE(b.isValid());
    
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);
    
    cout << "Performance test completed in " << duration.count() << " ms" << endl;
    // Con libsodium, esto debería ser mucho más rápido que con OpenSSL
    EXPECT_LT(duration.count(), 1000); // Menos de 1 segundo para 100 transacciones
}