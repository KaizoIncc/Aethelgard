#include <gtest/gtest.h>
#include <filesystem>
#include "BlockchainStorage.hpp"
#include "Block.hpp"
#include "Transaction.hpp"

namespace fs = filesystem;

class BlockchainStorageTest : public ::testing::Test {
protected:
    string testDir = "test_data";
    BlockchainStorage* storage;

    void SetUp() override {
        fs::remove_all(testDir); // limpiar antes
        storage = new BlockchainStorage(testDir);
        ASSERT_TRUE(storage->initialize());
    }

    void TearDown() override {
        delete storage;
        fs::remove_all(testDir); // limpiar después
    }
};

// ------------------- Inicialización -------------------
TEST_F(BlockchainStorageTest, InitializeCreatesDirectories) {
    EXPECT_TRUE(fs::exists(testDir));
    EXPECT_TRUE(fs::exists(testDir + "/blocks"));
    EXPECT_TRUE(fs::exists(testDir + "/transactions"));
    EXPECT_TRUE(fs::exists(testDir + "/chainstate.bin"));
}

// ------------------- Guardar y cargar bloques -------------------
TEST_F(BlockchainStorageTest, SaveAndLoadBlock) {
    Block block(0, "");
    EXPECT_TRUE(storage->saveBlock(block));

    Block loadedBlock;
    EXPECT_TRUE(storage->loadBlock(0, loadedBlock, false));
    EXPECT_EQ(loadedBlock.getHeader().getIndex(), 0);
}

// ------------------- Cargar último bloque -------------------
TEST_F(BlockchainStorageTest, LoadLastBlock) {
    Block b1(0, "");
    Block b2(1, "prevHash");
    storage->saveBlock(b1);
    storage->saveBlock(b2);

    Block lastBlock;
    EXPECT_TRUE(storage->loadLastBlock(lastBlock));
    EXPECT_EQ(lastBlock.getHeader().getIndex(), 1);
}

// ------------------- Conteo de bloques -------------------
TEST_F(BlockchainStorageTest, GetBlockCount) {
    EXPECT_EQ(storage->getBlockCount(), 0);
    storage->saveBlock(Block(0, ""));
    storage->saveBlock(Block(1, "0"));
    EXPECT_EQ(storage->getBlockCount(), 2);
}

// ------------------- Guardar y cargar chainstate -------------------
TEST_F(BlockchainStorageTest, SaveAndLoadChainState) {
    string state = "my_chain_state";
    EXPECT_TRUE(storage->saveChainState(state));
    EXPECT_EQ(storage->loadChainState(), state);
}

// ------------------- Guardar y cargar transacciones -------------------
TEST_F(BlockchainStorageTest, SaveAndLoadTransaction) {
    Transaction tx("from", "to", 10.0, "data");
    EXPECT_TRUE(storage->saveTransaction(tx));

    Transaction loadedTx;
    EXPECT_TRUE(storage->loadTransaction(tx.getHash(), loadedTx));
    EXPECT_EQ(loadedTx.getHash(), tx.getHash());
    EXPECT_EQ(loadedTx.getFrom(), tx.getFrom());
}

// ------------------- Obtener transacciones por dirección -------------------
TEST_F(BlockchainStorageTest, GetTransactionsByAddress) {
    Transaction tx1("A", "B", 5.0, "data");
    Transaction tx2("B", "A", 10.0, "data2");
    storage->saveTransaction(tx1);
    storage->saveTransaction(tx2);

    auto txsA = storage->getTransactionsByAddress("A");
    EXPECT_EQ(txsA.size(), 2);

    auto txsB = storage->getTransactionsByAddress("B");
    EXPECT_EQ(txsB.size(), 2);

    auto txsC = storage->getTransactionsByAddress("C");
    EXPECT_TRUE(txsC.empty());
}

// ------------------- ClearStorage -------------------
TEST_F(BlockchainStorageTest, ClearStorageResetsDirectories) {
    storage->saveBlock(Block(0, ""));
    storage->saveTransaction(Transaction("A", "B", 5.0, "data"));

    EXPECT_TRUE(storage->clearStorage());
    EXPECT_EQ(storage->getBlockCount(), 0);
    EXPECT_TRUE(storage->getAllBlockIndexes().empty());
}

// ------------------- Backup y restore -------------------
TEST_F(BlockchainStorageTest, BackupAndRestore) {
    Block b(0, "");
    storage->saveBlock(b);

    string backupDir = "backup_test";
    EXPECT_TRUE(storage->backup(backupDir));

    storage->clearStorage();
    EXPECT_EQ(storage->getBlockCount(), 0);

    EXPECT_TRUE(storage->restore(backupDir));
    EXPECT_EQ(storage->getBlockCount(), 1);

    fs::remove_all(backupDir);
}

// ------------------- Integridad de almacenamiento -------------------
TEST_F(BlockchainStorageTest, VerifyStorageIntegrity) {
    // Crear tres bloques para asegurar que la corrupción sea detectable
    Block b1(0, "");
    Block b2(1, "0");
    Block b3(2, "1");

    EXPECT_TRUE(storage->saveBlock(b1));
    EXPECT_TRUE(storage->saveBlock(b2));
    EXPECT_TRUE(storage->saveBlock(b3));

    // Verificar integridad inicial: todo correcto
    EXPECT_TRUE(storage->verifyStorageIntegrity());

    // Buscar el archivo del bloque 1 manualmente
    string blocksDir = "test_data/blocks";
    string corruptFile;
    for (const auto& entry : fs::directory_iterator(blocksDir)) {
        if (entry.is_regular_file() && entry.path().filename().string().find("block_") == 0) {
            // Extraer el índice del nombre del archivo
            string filename = entry.path().filename().string();
            size_t start = filename.find('_') + 1;
            size_t end = filename.find('.', start);
            if (start != string::npos && end != string::npos) {
                string indexStr = filename.substr(start, end - start);
                if (stoull(indexStr) == 1) {
                    corruptFile = entry.path().string();
                    break;
                }
            }
        }
    }
    ASSERT_FALSE(corruptFile.empty());
    ASSERT_TRUE(fs::exists(corruptFile)); // Aseguramos que existe antes de borrar
    fs::remove(corruptFile);
    ASSERT_FALSE(fs::exists(corruptFile)); // Confirmamos que se borró

    // Verificar integridad de nuevo ignorando la cache
    EXPECT_FALSE(storage->verifyStorageIntegrity());
}

// ------------------- Obtener todos los índices de bloques -------------------
TEST_F(BlockchainStorageTest, GetAllBlockIndexes) {
    storage->saveBlock(Block(0, ""));
    storage->saveBlock(Block(2, "0"));
    storage->saveBlock(Block(1, "0"));

    auto indexes = storage->getAllBlockIndexes();
    EXPECT_EQ(indexes.size(), 3);
    EXPECT_EQ(indexes[0], 0);
    EXPECT_EQ(indexes[1], 1);
    EXPECT_EQ(indexes[2], 2);
}

// ------------------- Valores límite y errores -------------------
TEST_F(BlockchainStorageTest, LoadNonExistingBlockFails) {
    Block b;
    EXPECT_FALSE(storage->loadBlock(999, b, false));
}

TEST_F(BlockchainStorageTest, LoadNonExistingTransactionFails) {
    Transaction tx;
    EXPECT_FALSE(storage->loadTransaction("nonexistent", tx));
}
