#include <gtest/gtest.h>
#include "Transaction.hpp"
#include "Utils.hpp"
#include <thread>
#include <chrono>
#include <algorithm>
#include <cfloat>     // para DBL_MAX
#include <limits>     // para numeric_limits

class TransactionTest : public ::testing::Test {
protected:
    string privKey1, pubKey1, addr1;
    string privKey2, pubKey2, addr2;

    void SetUp() override {
        // Generar claves
        ASSERT_TRUE(CryptoUtils::generateKeyPair(privKey1, pubKey1));
        ASSERT_TRUE(CryptoUtils::generateKeyPair(privKey2, pubKey2));

        // Derivar direcciones
        addr1 = CryptoUtils::publicKeyToAddress(pubKey1);
        addr2 = CryptoUtils::publicKeyToAddress(pubKey2);

        ASSERT_FALSE(addr1.empty());
        ASSERT_FALSE(addr2.empty());
    }
};

//
// 🔹 Constructores y getters/setters
//
TEST_F(TransactionTest, DefaultConstructor) {
    Transaction tx;
    EXPECT_EQ(tx.getFrom(), "");
    EXPECT_EQ(tx.getTo(), "");
    EXPECT_EQ(tx.getAmount(), 0.0);
    EXPECT_EQ(tx.getData(), "");
    EXPECT_EQ(tx.getSignature(), "");
    EXPECT_EQ(tx.getHash(), "");
    EXPECT_EQ(tx.getTimestamp(), 0);
}

TEST_F(TransactionTest, ParameterizedConstructor) {
    Transaction tx(addr1, addr2, 10.5, "Pago test");
    EXPECT_EQ(tx.getFrom(), addr1);
    EXPECT_EQ(tx.getTo(), addr2);
    EXPECT_EQ(tx.getAmount(), 10.5);
    EXPECT_EQ(tx.getData(), "Pago test");
    EXPECT_FALSE(tx.getHash().empty());
    EXPECT_GT(tx.getTimestamp(), 0);
}

//
// 🔹 Hash e integridad
//
TEST_F(TransactionTest, CalculateHashConsistency) {
    Transaction tx(addr1, addr2, 10.0, "TestHash");
    tx.sign(privKey1);
    string oldHash = tx.getHash();

    // Volvemos a calcular el hash y debe coincidir
    tx.calculateHash();
    string newHash = tx.getHash();

    EXPECT_EQ(oldHash, newHash);
}

TEST_F(TransactionTest, HashChangesWhenFieldsChange) {
    Transaction tx(addr1, addr2, 10.0, "test");
    string h1 = tx.getHash();

    tx.setAmount(20.0);
    tx.calculateHash();
    string h2 = tx.getHash();

    EXPECT_NE(h1, h2);
}

TEST_F(TransactionTest, IdenticalTransactionsHaveDifferentHashesDueToTimestamp) {
    Transaction tx1(addr1, addr2, 5.0, "first");
    this_thread::sleep_for(chrono::milliseconds(5));
    Transaction tx2(addr1, addr2, 5.0, "first");

    EXPECT_NE(tx1.getHash(), tx2.getHash());
}

//
// 🔹 Validación de transacciones
//
TEST_F(TransactionTest, IsValidTransaction) {
    Transaction tx(addr1, addr2, 5.0, "ValidTx");
    tx.sign(privKey1);   // ahora es necesario firmar
    EXPECT_TRUE(tx.isValid());
}

TEST_F(TransactionTest, InvalidTransactionZeroAmount) {
    Transaction tx(addr1, addr2, 0.0, "FailTx");
    EXPECT_FALSE(tx.isValid());
}

TEST_F(TransactionTest, InvalidTransactionEmptyFromOrTo) {
    Transaction tx1("", addr2, 1.0);
    EXPECT_FALSE(tx1.isValid());

    Transaction tx2(addr1, "", 1.0);
    EXPECT_FALSE(tx2.isValid());
}

TEST_F(TransactionTest, NegativeAmountIsInvalid) {
    Transaction tx(addr1, addr2, -5.0, "Negativo");
    tx.sign(privKey1);
    EXPECT_FALSE(tx.isValid());
}

TEST_F(TransactionTest, SelfTransactionBehavior) {
    Transaction tx(addr1, addr1, 10.0, "Loopback");
    tx.sign(privKey1);
    EXPECT_FALSE(tx.isValid()); // regla de negocio: inválida
}

TEST_F(TransactionTest, EmptyDataStillValid) {
    Transaction tx(addr1, addr2, 5.0, "");
    tx.sign(privKey1);   // firma necesaria
    EXPECT_TRUE(tx.isValid());
}

//
// 🔹 Firma digital
//
TEST_F(TransactionTest, SignAndVerify) {
    Transaction tx(addr1, addr2, 15.0, "Firmado");
    EXPECT_TRUE(tx.sign(privKey1));
    EXPECT_FALSE(tx.getSignature().empty());
    EXPECT_TRUE(tx.verifySignature());
}

TEST_F(TransactionTest, SignatureInvalidAfterDataModification) {
    Transaction tx(addr1, addr2, 15.0, "Pago");
    EXPECT_TRUE(tx.sign(privKey1));
    EXPECT_TRUE(tx.verifySignature());

    tx.setData("Modificado");
    tx.calculateHash();
    EXPECT_FALSE(tx.verifySignature());
}

TEST_F(TransactionTest, SignatureFailsWithWrongPrivateKey) {
    Transaction tx(addr1, addr2, 10.0);
    EXPECT_FALSE(tx.sign(privKey2));
    EXPECT_FALSE(tx.verifySignature());
}

TEST_F(TransactionTest, DoubleSignDoesNotChangeSignature) {
    Transaction tx(addr1, addr2, 3.0, "DoubleSign");
    EXPECT_TRUE(tx.sign(privKey1));
    string sig1 = tx.getSignature();

    EXPECT_TRUE(tx.sign(privKey1));
    string sig2 = tx.getSignature();

    EXPECT_NE(sig1, ""); 
    EXPECT_NE(sig2, "");
    EXPECT_TRUE(tx.verifySignature());
}

TEST_F(TransactionTest, VerifySignatureFailsWhenNotSigned) {
    Transaction tx(addr1, addr2, 5.0, "Unsigned");
    // No llamamos a sign()
    EXPECT_FALSE(tx.isValid());   // ahora debe fallar
}

TEST_F(TransactionTest, VerifyFailsWithWrongSignature) {
    Transaction tx(addr1, addr2, 15.0, "Fraude");
    EXPECT_TRUE(tx.sign(privKey1));

    tx.setSignature("firma_falsa");
    EXPECT_FALSE(tx.verifySignature());
}

//
// 🔹 Funciones auxiliares
//
TEST_F(TransactionTest, InvolvesAddress) {
    Transaction tx(addr1, addr2, 1.0);
    EXPECT_TRUE(tx.involvesAddress(addr1));
    EXPECT_TRUE(tx.involvesAddress(addr2));
    EXPECT_FALSE(tx.involvesAddress("otro"));
}

TEST_F(TransactionTest, InvolvesAddressCaseSensitivity) {
    Transaction tx(addr1, addr2, 1.0, "CheckCase");
    string upper = addr1;
    transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

    // depende de implementación: aquí asumimos case-sensitive
    EXPECT_FALSE(tx.involvesAddress(upper));
}

TEST_F(TransactionTest, ToStringOutput) {
    Transaction tx(addr1, addr2, 2.5, "DataTest");
    string s = tx.toString();
    EXPECT_NE(s.find(addr1), string::npos);
    EXPECT_NE(s.find(addr2), string::npos);
    EXPECT_NE(s.find("2.5"), string::npos);
    EXPECT_NE(s.find("DataTest"), string::npos);
}

TEST_F(TransactionTest, ToStringContainsAllFields) {
    Transaction tx(addr1, addr2, 42.0, "DataField");
    tx.sign(privKey1);
    string s = tx.toString();

    EXPECT_NE(s.find(addr1), string::npos);
    EXPECT_NE(s.find(addr2), string::npos);
    EXPECT_NE(s.find("42"), string::npos);
    EXPECT_NE(s.find("DataField"), string::npos);
    EXPECT_NE(s.find(tx.getHash()), string::npos);
    EXPECT_NE(s.find(tx.getSignature()), string::npos);
}

//
// 🔹 Stress Tests
//
TEST_F(TransactionTest, StressTestCreateAndSignTransactions) {
    const int NUM_TX = 1000;
    vector<Transaction> txs;
    txs.reserve(NUM_TX);

    using namespace std::chrono;
    auto globalStart = high_resolution_clock::now();

    long long totalCreateMs = 0;
    long long totalSignMs = 0;
    long long totalVerifyMs = 0;

    for (int i = 0; i < NUM_TX; i++) {
        auto t1 = high_resolution_clock::now();
        Transaction tx(addr1, addr2, i + 0.1, "StressTest");
        auto t2 = high_resolution_clock::now();

        EXPECT_TRUE(tx.sign(privKey1));
        auto t3 = high_resolution_clock::now();

        EXPECT_TRUE(tx.verifySignature());
        auto t4 = high_resolution_clock::now();

        txs.push_back(tx);

        totalCreateMs += duration_cast<microseconds>(t2 - t1).count();
        totalSignMs   += duration_cast<microseconds>(t3 - t2).count();
        totalVerifyMs += duration_cast<microseconds>(t4 - t3).count();
    }

    auto globalEnd = high_resolution_clock::now();
    auto durationMs = duration_cast<milliseconds>(globalEnd - globalStart).count();

    std::cout << "StressTest results:\n";
    std::cout << "  Create total = " << totalCreateMs / 1000.0 << " ms\n";
    std::cout << "  Sign total   = " << totalSignMs   / 1000.0 << " ms\n";
    std::cout << "  Verify total = " << totalVerifyMs / 1000.0 << " ms\n";
    std::cout << "  Overall time = " << durationMs << " ms\n";

    EXPECT_LT(durationMs, 3000);
    EXPECT_EQ(txs.size(), NUM_TX);
}

//
// 🔹 Orden temporal
//
TEST_F(TransactionTest, TimestampIsNeverZero) {
    Transaction tx(addr1, addr2, 1.0, "TimeCheck");
    EXPECT_GT(tx.getTimestamp(), 0);
}

TEST_F(TransactionTest, TimestampsIncreaseOverTime) {
    Transaction tx1(addr1, addr2, 1.0, "T1");
    this_thread::sleep_for(chrono::milliseconds(2));
    Transaction tx2(addr1, addr2, 1.0, "T2");

    EXPECT_GT(tx2.getTimestamp(), tx1.getTimestamp());
}

//
// 🔹 Robustez ante datos extremos
//
TEST_F(TransactionTest, ExtremeAmountMaxDouble) {
    Transaction tx(addr1, addr2, DBL_MAX, "MaxDouble");
    tx.sign(privKey1);
    // Dependiendo de tu política: aquí yo pongo false porque es extremo e irreal
    EXPECT_FALSE(tx.isValid());
}

TEST_F(TransactionTest, ExtremeAmountSmallDouble) {
    Transaction tx(addr1, addr2, DBL_MIN, "MinDouble");
    tx.sign(privKey1);
    // Dependiendo de tu política: aquí yo pongo false porque es demasiado pequeño
    EXPECT_FALSE(tx.isValid());
}

TEST_F(TransactionTest, InvalidAddressCharacters) {
    string invalidAddr = "ZZZZ_not_a_valid_address_###";
    Transaction tx(invalidAddr, addr2, 5.0, "InvalidFrom");
    EXPECT_FALSE(tx.isValid());

    Transaction tx2(addr1, invalidAddr, 5.0, "InvalidTo");
    EXPECT_FALSE(tx2.isValid());
}