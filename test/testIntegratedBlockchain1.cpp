#include <gtest/gtest.h>
#include "Block.hpp"
#include "BlockHeader.hpp"
#include "Transaction.hpp"
#include "BlockchainStorage.hpp"
#include "Utils.hpp"

#include <filesystem>
#include <fstream>
#include <regex>

namespace fs = filesystem;

// ---------- FIXTURE ----------
class IntegrationTest : public ::testing::Test {
protected:
    string testDir = "test_data";

    void SetUp() override {
        fs::remove_all(testDir);
        fs::create_directories(testDir);
    }

    void TearDown() override {
        fs::remove_all(testDir);
    }
};

// ---------- TESTS ----------

// 1. CryptoUtils: generación y verificación de claves
TEST_F(IntegrationTest, Crypto_KeyGen_Sign_Verify) {
    string priv, pub;
    ASSERT_TRUE(CryptoUtils::generateKeyPair(priv, pub));
    ASSERT_TRUE(CryptoUtils::isValidPrivateKey(priv));
    ASSERT_TRUE(CryptoUtils::isValidPublicKey(pub));

    string msg = "Hola Blockchain";
    // Convertir a hex para que funcione con tu implementación actual
    string msgHex = CryptoBase::bytesToHex(vector<uint8_t>(msg.begin(), msg.end()));
    
    string sig = CryptoUtils::signMessage(priv, msgHex); // Pasar el hex

    ASSERT_TRUE(CryptoUtils::verifySignature(pub, msg, sig)); // Pero verify espera texto plano - ¡inconsistente!
}

// 2. Transaction: creación válida e inválida
TEST_F(IntegrationTest, Transaction_Valid_Invalid) {
    // Generar primer par de claves
    string priv1, pub1;
    ASSERT_TRUE(CryptoUtils::generateKeyPair(priv1, pub1));
    string addr1 = CryptoUtils::publicKeyToAddress(pub1);

    // Generar segundo par de claves para el destinatario
    string priv2, pub2;
    ASSERT_TRUE(CryptoUtils::generateKeyPair(priv2, pub2));
    string addr2 = CryptoUtils::publicKeyToAddress(pub2);

    // Crear transacción válida
    Transaction tx(addr1, addr2, 10.0, "Pago test");
    ASSERT_TRUE(tx.sign(priv1));
    EXPECT_TRUE(tx.isValid());

    // Crear transacción inválida (misma dirección)
    Transaction txInvalid(addr1, addr1, 5.0, "Loop");
    EXPECT_FALSE(txInvalid.sign(priv1));
    EXPECT_FALSE(txInvalid.isValid());
}

// 3. Block: agregar transacciones y validar hash
TEST_F(IntegrationTest, Block_AddTransactions) {
    // Generar dos pares de claves para direcciones válidas
    string priv1, pub1, priv2, pub2;
    CryptoUtils::generateKeyPair(priv1, pub1);
    CryptoUtils::generateKeyPair(priv2, pub2);
    
    string addr1 = CryptoUtils::publicKeyToAddress(pub1);
    string addr2 = CryptoUtils::publicKeyToAddress(pub2);

    Block b(1, "prev");
    Transaction tx(addr1, addr2, 42, "Pago X");  // Usar addr2 válida
    ASSERT_TRUE(tx.sign(priv1));
    
    ASSERT_TRUE(b.addTransaction(tx));

    EXPECT_EQ(b.getTransactionCount(), 1);
    EXPECT_TRUE(b.isValid());
}

// 4. BlockchainStorage: guardar y recuperar bloque
TEST_F(IntegrationTest, Storage_Save_Load_Block) {
    BlockchainStorage storage(testDir);
    ASSERT_TRUE(storage.initialize());

    Block b1(0, "");
    Block b2(1, "prev");
    storage.saveBlock(b1);
    storage.saveBlock(b2);

    EXPECT_EQ(storage.getBlockCount(), 2);

    Block loaded;
    ASSERT_TRUE(storage.loadBlock(1, loaded, true));
    EXPECT_EQ(loaded.getHeader().getIndex(), 1);
}

// 5. BlockchainStorage: transacciones
TEST_F(IntegrationTest, Storage_Save_Load_Transaction) {
    BlockchainStorage storage(testDir);
    ASSERT_TRUE(storage.initialize());

    // Generar dos pares de claves para direcciones válidas
    string priv1, pub1, priv2, pub2;
    CryptoUtils::generateKeyPair(priv1, pub1);
    CryptoUtils::generateKeyPair(priv2, pub2);
    
    string addrFrom = CryptoUtils::publicKeyToAddress(pub1);
    string addrTo = CryptoUtils::publicKeyToAddress(pub2);
    
    Transaction tx(addrFrom, addrTo, 50.0, "Test TX");
    ASSERT_TRUE(tx.sign(priv1));
    ASSERT_TRUE(tx.isValid());

    ASSERT_TRUE(storage.saveTransaction(tx));

    Transaction loaded;
    ASSERT_TRUE(storage.loadTransaction(tx.getHash(), loaded));
    EXPECT_EQ(loaded.getHash(), tx.getHash());

    auto txs = storage.getTransactionsByAddress(addrFrom);
    EXPECT_FALSE(txs.empty());
}

// 6. BlockchainStorage: integridad
TEST_F(IntegrationTest, Storage_VerifyIntegrity) {
    BlockchainStorage storage(testDir);
    ASSERT_TRUE(storage.initialize());

    Block b1(0, "");
    Block b2(1, "prev");
    storage.saveBlock(b1);
    storage.saveBlock(b2);

    EXPECT_TRUE(storage.verifyStorageIntegrity());

    // Simular corrupción: borrar un archivo de bloque sin usar getBlockFilename()
    auto indexes = storage.getAllBlockIndexes();
    ASSERT_FALSE(indexes.empty());

    // Buscar el archivo correspondiente al índice más alto (busca recursivamente y admite ceros rellenos)
    string blockFile;
    regex re(R"(block_0*([0-9]+)\.blk$)"); // captura el índice ignorando ceros a la izquierda

    try {
        for (const auto& entry : fs::recursive_directory_iterator(testDir)) {
            if (!entry.is_regular_file()) continue;
            string filename = entry.path().filename().string();

            smatch m;
            if (regex_search(filename, m, re) && m.size() >= 2) {
                uint64_t idx = stoull(m[1].str());
                if (idx == indexes.back()) {
                    blockFile = entry.path().string();
                    break;
                }
            }
        }
    } catch (const exception& e) {
        FAIL() << "Error iterating directory '" << testDir << "': " << e.what();
    }

    ASSERT_FALSE(blockFile.empty());
    
    std::ofstream corrupt(blockFile, std::ios::binary | std::ios::trunc);
    corrupt << "CORRUPTED DATA";
    corrupt.close();

    EXPECT_FALSE(storage.verifyStorageIntegrity());
}
