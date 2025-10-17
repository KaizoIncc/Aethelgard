#include <gtest/gtest.h>
#include "Block.hpp"
#include "BlockHeader.hpp"
#include "Transaction.hpp"
#include "CryptoBase.hpp"
#include "KeyManager.hpp"
#include "AddressManager.hpp"
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <algorithm>
#include <sstream>
#include <memory>
#include <thread>

// ============================================================================
// FIXTURE PRINCIPAL PARA TESTS DE BLOCK
// ============================================================================

class BlockTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Inicializar dependencias criptográficas
        ASSERT_TRUE(CryptoBase::initialize()) << "Failed to initialize crypto libraries";
        
        // Inicializar métricas
        testMetrics.clear();
        testStartTime = std::chrono::high_resolution_clock::now();
        
        // Generar datos de prueba
        generateTestData();
        debugAddresses();
    }
    
    void TearDown() override {
        // Limpieza segura de datos sensibles
        CryptoBase::secureClean(testPrivateKey);
        CryptoBase::secureClean(testPublicKey);
        
        // Calcular métricas finales
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - testStartTime);
        testMetrics["total_test_duration_ms"] = duration.count();
        
        // Log de métricas resumidas
        std::cout << "[METRICS] BlockTest completed - Duration: " 
                  << duration.count() << "ms" << std::endl;
        for (const auto& [key, value] : testMetrics) {
            if (value > 0) {
                std::cout << "[METRIC] " << key << ": " << value << std::endl;
            }
        }
    }

    void debugVectorInfo(const std::string& name, const std::vector<uint8_t>& vec) {
        std::cout << "DEBUG " << name << ": size=" << vec.size() 
                << ", capacity=" << vec.capacity() 
                << ", data_ptr=" << static_cast<const void*>(vec.data()) 
                << ", empty=" << vec.empty() << std::endl;
    }
    
    void generateTestData() {
        // Generar PRIMER par de claves
        std::vector<uint8_t> privateKey1(PRIVATE_KEY_SIZE);
        std::vector<uint8_t> publicKey1(PUBLIC_KEY_SIZE);
        
        ASSERT_TRUE(KeyManager::generateKeyPair(privateKey1, publicKey1));
        testFromAddress = AddressManager::getAddressFromPublicKey(publicKey1);
        
        // Pequeña pausa para asegurar aleatoriedad
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        
        // Generar SEGUNDO par de claves
        std::vector<uint8_t> privateKey2(PRIVATE_KEY_SIZE);
        std::vector<uint8_t> publicKey2(PUBLIC_KEY_SIZE);
        
        ASSERT_TRUE(KeyManager::generateKeyPair(privateKey2, publicKey2));
        testToAddress = AddressManager::getAddressFromPublicKey(publicKey2);

        ASSERT_NE(testFromAddress, testToAddress) << "Addresses should be different!";
        
        // Guardar las claves para usar en las transacciones
        testPrivateKey = privateKey1;
        testPublicKey = publicKey1;
        
        // Generar hash válido
        validHash = generateValidHash();
        
        // Limpieza segura
        CryptoBase::secureClean(privateKey2);
        CryptoBase::secureClean(publicKey2);
    }
    
    // Helper para generar hash válido
    std::vector<uint8_t> generateValidHash() {
        std::vector<uint8_t> hash(SHA256_HASH_SIZE);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1, 255); // Evitar ceros
        
        for (size_t i = 0; i < SHA256_HASH_SIZE; ++i) {
            hash[i] = static_cast<uint8_t>(dis(gen));
        }
        return hash;
    }
    
    // Helper para crear transacción válida firmada
    // Helper para crear transacción válida firmada
    Transaction createSignedTransaction(double amount = 1.0, const std::string& data = "") {
        // Crear la transacción
        Transaction tx(testFromAddress, testToAddress, amount, data);
        
        // Firmar la transacción
        bool signResult = tx.sign(testPrivateKey);
        EXPECT_TRUE(signResult);
        
        return tx;
    }
    
    // Helper para crear bloque génesis
    std::unique_ptr<Block> createGenesisBlock() {
        std::vector<uint8_t> genesisPreviousHash(SHA256_HASH_SIZE, 0x00);
        return std::make_unique<Block>(0, genesisPreviousHash);
    }
    
    // Helper para crear bloque normal
    std::unique_ptr<Block> createNormalBlock(int64_t index = 1) {
        return std::make_unique<Block>(index, validHash);
    }
    
    // Helper para crear bloque con transacciones
    std::unique_ptr<Block> createBlockWithTransactions(int64_t index = 1, int txCount = 3) {
        auto block = createNormalBlock(index);
        
        for (int i = 0; i < txCount; ++i) {
            Transaction tx = createSignedTransaction(0.1 + i * 0.1, "tx " + std::to_string(i));
            EXPECT_TRUE(block->addTransaction(tx));
        }
        
        return block;
    }
    
    // Helper para debug
    template<typename T>
    void debugLog(const std::string& testName, const T& actual, const T& expected) {
        std::cout << "[DEBUG] " << testName 
                  << " - Actual: " << actual 
                  << " | Expected: " << expected 
                  << std::endl;
    }

    void debugAddresses() {
        std::cout << "DEBUG Addresses - From: " << testFromAddress 
                << " | To: " << testToAddress 
                << " | Same: " << (testFromAddress == testToAddress ? "YES" : "NO")
                << std::endl;
    }
    
    // Métricas
    std::map<std::string, double> testMetrics;
    std::chrono::high_resolution_clock::time_point testStartTime;
    
    // Datos de prueba
    std::vector<uint8_t> testPrivateKey;
    std::vector<uint8_t> testPublicKey;
    std::string testFromAddress;
    std::string testToAddress;
    std::vector<uint8_t> validHash;
};

// ============================================================================
// SECCIÓN 1: TESTS BÁSICOS DE CONSTRUCCIÓN
// ============================================================================

TEST_F(BlockTest, ConstructorDefault) {
    auto start = std::chrono::high_resolution_clock::now();
    
    Block block;
    
    // Verificar que se creó un bloque génesis por defecto
    EXPECT_EQ(block.getHeader().getIndex(), 0);
    EXPECT_TRUE(block.getTransactions().empty());
    EXPECT_EQ(block.getTransactionCount(), 0);
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["constructor_default_ms"] = 
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
}

TEST_F(BlockTest, ConstructorGenesisBlock) {
    auto start = std::chrono::high_resolution_clock::now();
    
    std::unique_ptr<Block> genesis = createGenesisBlock();
    
    EXPECT_EQ(genesis->getHeader().getIndex(), 0);
    EXPECT_TRUE(genesis->getTransactions().empty());
    
    // El previousHash del génesis puede ser todo ceros
    std::vector<uint8_t> previousHash = genesis->getHeader().getPreviousHash();
    EXPECT_TRUE(std::all_of(previousHash.begin(), previousHash.end(), 
                           [](uint8_t b) { return b == 0; }));
    
    // El hash del bloque debería estar calculado
    EXPECT_FALSE(genesis->getHeader().getHash().empty());
    EXPECT_EQ(genesis->getHeader().getHash().size(), SHA256_HASH_SIZE);
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["constructor_genesis_ms"] = 
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
}

TEST_F(BlockTest, ConstructorNormalBlock) {
    auto start = std::chrono::high_resolution_clock::now();
    
    std::unique_ptr<Block> block = createNormalBlock(42);
    
    EXPECT_EQ(block->getHeader().getIndex(), 42);
    EXPECT_EQ(block->getHeader().getPreviousHash(), validHash);
    EXPECT_TRUE(block->getTransactions().empty());
    
    // El hash del bloque debería estar calculado
    EXPECT_FALSE(block->getHeader().getHash().empty());
    EXPECT_EQ(block->getHeader().getHash().size(), SHA256_HASH_SIZE);
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["constructor_normal_ms"] = 
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
}

// ============================================================================
// SECCIÓN 2: TESTS DE VALIDACIÓN DE ENTRADA Y ERRORES
// ============================================================================

TEST_F(BlockTest, ConstructorNegativeIndexThrowsException) {
    EXPECT_THROW({
        Block block(-1, validHash);
    }, std::invalid_argument);
    
    EXPECT_THROW({
        Block block(-100, validHash);
    }, std::invalid_argument);
}

// ============================================================================
// SECCIÓN 3: TESTS DE GESTIÓN DE TRANSACCIONES
// ============================================================================

TEST_F(BlockTest, AddValidTransaction) {
    auto start = std::chrono::high_resolution_clock::now();
    
    std::unique_ptr<Block> block = createNormalBlock(1);
    
    Transaction tx = createSignedTransaction(1.5, "test transaction");
    
    EXPECT_TRUE(block->addTransaction(tx));    
    EXPECT_EQ(block->getTransactionCount(), 1);
    EXPECT_EQ(block->getTransactions().size(), 1);
    
    // El hash del bloque debería haberse actualizado
    EXPECT_FALSE(block->getHeader().getHash().empty());
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["add_valid_transaction_ms"] = 
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    std::cout << "DEBUG: Test completed successfully" << std::endl;
}

TEST_F(BlockTest, AddInvalidTransactionFails) {
    std::unique_ptr<Block> block = createNormalBlock(1);
    
    // Transacción no firmada (inválida)
    Transaction invalidTx(testFromAddress, testToAddress, 1.0, "unsigned");
    
    EXPECT_FALSE(block->addTransaction(invalidTx));
    EXPECT_EQ(block->getTransactionCount(), 0);
}

TEST_F(BlockTest, AddMultipleTransactions) {
    const int txCount = 5;
    std::unique_ptr<Block> block = createNormalBlock(1);
    
    for (int i = 0; i < txCount; ++i) {
        Transaction tx = createSignedTransaction(0.1 + i * 0.5, "tx " + std::to_string(i));
        EXPECT_TRUE(block->addTransaction(tx));
    }
    
    EXPECT_EQ(block->getTransactionCount(), txCount);
    
    // Verificar que todas las transacciones están presentes
    const auto& transactions = block->getTransactions();
    for (int i = 0; i < txCount; ++i) {
        EXPECT_DOUBLE_EQ(transactions[i].getAmount(), 0.1 + i * 0.5);
    }
}

TEST_F(BlockTest, TransactionOrderPreserved) {
    std::unique_ptr<Block> block = createNormalBlock(1);
    
    Transaction tx1 = createSignedTransaction(1.0, "first");
    Transaction tx2 = createSignedTransaction(2.0, "second");
    Transaction tx3 = createSignedTransaction(3.0, "third");
    
    EXPECT_TRUE(block->addTransaction(tx1));
    EXPECT_TRUE(block->addTransaction(tx2));
    EXPECT_TRUE(block->addTransaction(tx3));
    
    const auto& transactions = block->getTransactions();
    EXPECT_EQ(transactions.size(), 3);
    EXPECT_DOUBLE_EQ(transactions[0].getAmount(), 1.0);
    EXPECT_DOUBLE_EQ(transactions[1].getAmount(), 2.0);
    EXPECT_DOUBLE_EQ(transactions[2].getAmount(), 3.0);
}

// ============================================================================
// SECCIÓN 4: TESTS DE CÁLCULO DE MERKLE ROOT
// ============================================================================

TEST_F(BlockTest, CalculateMerkleRootEmptyBlock) {
    std::unique_ptr<Block> block = createNormalBlock(1);
    
    std::vector<uint8_t> merkleRoot = block->calculateMerkleRoot();
    
    // Merkle root de bloque vacío debería ser hash de datos vacíos
    EXPECT_FALSE(merkleRoot.empty());
    EXPECT_EQ(merkleRoot.size(), SHA256_HASH_SIZE);
    
    // No debería ser todo ceros
    EXPECT_FALSE(std::all_of(merkleRoot.begin(), merkleRoot.end(), 
                            [](uint8_t b) { return b == 0; }));
}

TEST_F(BlockTest, CalculateMerkleRootSingleTransaction) {
    std::unique_ptr<Block> block = createNormalBlock(1);
    Transaction tx = createSignedTransaction(1.0, "single tx");
    
    EXPECT_TRUE(block->addTransaction(tx));
    
    std::vector<uint8_t> merkleRoot = block->calculateMerkleRoot();
    
    EXPECT_FALSE(merkleRoot.empty());
    EXPECT_EQ(merkleRoot.size(), SHA256_HASH_SIZE);
    
    // Para una transacción, el merkle root debería ser el hash de esa transacción
    // (o hash(tx_hash + tx_hash) dependiendo de la implementación)
}

TEST_F(BlockTest, CalculateMerkleRootMultipleTransactions) {
    const int txCount = 4;
    std::unique_ptr<Block> block = createNormalBlock(1);
    
    for (int i = 0; i < txCount; ++i) {
        Transaction tx = createSignedTransaction(0.1 + i * 0.1, "tx " + std::to_string(i));
        EXPECT_TRUE(block->addTransaction(tx));
    }
    
    std::vector<uint8_t> merkleRoot = block->calculateMerkleRoot();
    
    EXPECT_FALSE(merkleRoot.empty());
    EXPECT_EQ(merkleRoot.size(), SHA256_HASH_SIZE);
    
    // El merkle root debería ser consistente
    std::vector<uint8_t> merkleRoot2 = block->calculateMerkleRoot();
    EXPECT_EQ(merkleRoot, merkleRoot2);
}

TEST_F(BlockTest, CalculateMerkleRootOddNumberOfTransactions) {
    const int txCount = 3; // Número impar
    std::unique_ptr<Block> block = createNormalBlock(1);
    
    for (int i = 0; i < txCount; ++i) {
        Transaction tx = createSignedTransaction(0.1 + i * 0.1, "tx " + std::to_string(i));
        EXPECT_TRUE(block->addTransaction(tx));
    }
    
    std::vector<uint8_t> merkleRoot = block->calculateMerkleRoot();
    
    EXPECT_FALSE(merkleRoot.empty());
    EXPECT_EQ(merkleRoot.size(), SHA256_HASH_SIZE);
}

TEST_F(BlockTest, MerkleRootChangesWithTransactionOrder) {
    // Crear dos bloques con las mismas transacciones en orden diferente
    auto block1 = createNormalBlock(1);
    auto block2 = createNormalBlock(1);
    
    Transaction tx1 = createSignedTransaction(1.0, "first");
    Transaction tx2 = createSignedTransaction(2.0, "second");
    
    // Añadir en orden diferente
    EXPECT_TRUE(block1->addTransaction(tx1));
    EXPECT_TRUE(block1->addTransaction(tx2));
    
    EXPECT_TRUE(block2->addTransaction(tx2));
    EXPECT_TRUE(block2->addTransaction(tx1));
    
    std::vector<uint8_t> merkleRoot1 = block1->calculateMerkleRoot();
    std::vector<uint8_t> merkleRoot2 = block2->calculateMerkleRoot();
    
    // Los merkle roots deberían ser diferentes
    EXPECT_NE(merkleRoot1, merkleRoot2);
}

// ============================================================================
// SECCIÓN 5: TESTS DE CÁLCULO DE HASH DEL BLOQUE
// ============================================================================

TEST_F(BlockTest, CalculateBlockHashEmptyBlock) {
    std::unique_ptr<Block> block = createNormalBlock(1);
    
    std::vector<uint8_t> blockHash = block->calculateBlockHash();
    
    EXPECT_FALSE(blockHash.empty());
    EXPECT_EQ(blockHash.size(), SHA256_HASH_SIZE);
    EXPECT_EQ(blockHash, block->getHeader().getHash());
}

TEST_F(BlockTest, CalculateBlockHashWithTransactions) {
    std::unique_ptr<Block> block = createNormalBlock(1);
    
    Transaction tx = createSignedTransaction(1.0, "test");
    EXPECT_TRUE(block->addTransaction(tx));
    
    std::vector<uint8_t> blockHash = block->calculateBlockHash();
    
    EXPECT_FALSE(blockHash.empty());
    EXPECT_EQ(blockHash.size(), SHA256_HASH_SIZE);
    EXPECT_EQ(blockHash, block->getHeader().getHash());
}

TEST_F(BlockTest, BlockHashChangesWithTransactions) {
    auto block1 = createNormalBlock(1);
    auto block2 = createNormalBlock(1);
    
    std::vector<uint8_t> hash1 = block1->getHeader().getHash();
    
    Transaction tx = createSignedTransaction(1.0, "changes hash");
    EXPECT_TRUE(block2->addTransaction(tx));
    
    std::vector<uint8_t> hash2 = block2->getHeader().getHash();
    
    // Los hashes deberían ser diferentes
    EXPECT_NE(hash1, hash2);
}

TEST_F(BlockTest, BlockHashChangesWithMerkleRoot) {
    // El hash del bloque debería cambiar cuando cambia el merkle root
    auto block = createNormalBlock(1);
    std::vector<uint8_t> originalHash = block->getHeader().getHash();
    
    Transaction tx = createSignedTransaction(1.0, "changes merkle root");
    EXPECT_TRUE(block->addTransaction(tx));
    
    std::vector<uint8_t> newHash = block->getHeader().getHash();
    
    EXPECT_NE(originalHash, newHash);
}

TEST_F(BlockTest, BlockHashConsistency) {
    auto block = createNormalBlock(1);
    
    std::vector<uint8_t> hash1 = block->getHeader().getHash();
    std::vector<uint8_t> hash2 = block->calculateBlockHash();
    
    // El hash debería ser consistente
    EXPECT_EQ(hash1, hash2);
    
    // Múltiples llamadas deberían producir el mismo resultado
    std::vector<uint8_t> hash3 = block->calculateBlockHash();
    EXPECT_EQ(hash2, hash3);
}

// ============================================================================
// SECCIÓN 6: TESTS DE VALIDACIÓN DEL BLOQUE
// ============================================================================

TEST_F(BlockTest, IsValidEmptyBlock) {
    std::unique_ptr<Block> block = createNormalBlock(1);
    
    EXPECT_TRUE(block->isValid());
}

TEST_F(BlockTest, IsValidBlockWithTransactions) {
    std::unique_ptr<Block> block = createBlockWithTransactions(1, 3);
    
    EXPECT_TRUE(block->isValid());
}

TEST_F(BlockTest, IsValidGenesisBlock) {
    std::unique_ptr<Block> genesis = createGenesisBlock();
    
    EXPECT_TRUE(genesis->isValid());
}

TEST_F(BlockTest, IsValidFailsWithInvalidTransaction) {
    std::unique_ptr<Block> block = createNormalBlock(1);
    
    // Añadir transacción inválida (no firmada)
    Transaction invalidTx(testFromAddress, testToAddress, 1.0, "invalid");
    
    // Usar setTransactions para bypass la validación de addTransaction
    std::vector<Transaction> transactions = {invalidTx};
    block->setTransactions(transactions);
    
    EXPECT_FALSE(block->isValid());
}

TEST_F(BlockTest, IsValidFailsWithTamperedHeaderHash) {
    std::unique_ptr<Block> block = createNormalBlock(1);
    
    // Modificar el hash del header
    BlockHeader tamperedHeader = block->getHeader();
    std::vector<uint8_t> wrongHash(SHA256_HASH_SIZE, 0x99);
    tamperedHeader.setHash(wrongHash);
    block->setHeader(tamperedHeader);
    
    EXPECT_FALSE(block->isValid());
}

TEST_F(BlockTest, IsValidFailsWithTamperedMerkleRoot) {
    std::unique_ptr<Block> block = createBlockWithTransactions(1, 2);
    
    // Modificar el merkle root
    BlockHeader tamperedHeader = block->getHeader();
    std::vector<uint8_t> wrongMerkleRoot(SHA256_HASH_SIZE, 0x88);
    tamperedHeader.setMerkleRoot(wrongMerkleRoot);
    block->setHeader(tamperedHeader);
    
    EXPECT_FALSE(block->isValid());
}

TEST_F(BlockTest, IsValidFailsWithInvalidPreviousHashForNormalBlock) {
    // Bloque normal con previousHash inválido (todo ceros)
    std::vector<uint8_t> invalidPreviousHash(SHA256_HASH_SIZE, 0x00);
    
    EXPECT_THROW({
        Block block(1, invalidPreviousHash); // Debería lanzar excepción en constructor
    }, std::invalid_argument);
}

// ============================================================================
// SECCIÓN 7: TESTS DE LÍMITES DE CAPACIDAD
// ============================================================================

TEST_F(BlockTest, HasSpaceForTransactionWithinLimits) {
    std::unique_ptr<Block> block = createNormalBlock(1);
    
    Transaction tx = createSignedTransaction(1.0, "test");
    
    EXPECT_TRUE(block->hasSpaceForTransaction(tx));
}

TEST_F(BlockTest, TransactionCountLimit) {
    std::unique_ptr<Block> block = createNormalBlock(1);
    
    // Añadir transacciones hasta el límite
    int addedCount = 0;
    for (int i = 0; i < MAX_TRANSACTIONS + 10; ++i) {
        Transaction tx = createSignedTransaction(0.001, "tx " + std::to_string(i));
        if (block->addTransaction(tx)) {
            addedCount++;
        } else {
            break;
        }
    }
    
    // No deberíamos poder exceder MAX_TRANSACTIONS
    EXPECT_LE(addedCount, MAX_TRANSACTIONS);
    EXPECT_LE(block->getTransactionCount(), MAX_TRANSACTIONS);
}

TEST_F(BlockTest, BlockSizeEstimation) {
    std::unique_ptr<Block> block = createNormalBlock(1);
    
    size_t emptySize = block->getEstimatedSize();
    EXPECT_GT(emptySize, 0);
    
    // Añadir una transacción debería aumentar el tamaño estimado
    Transaction tx = createSignedTransaction(1.0, "test");
    EXPECT_TRUE(block->addTransaction(tx));
    
    size_t withTransactionSize = block->getEstimatedSize();
    EXPECT_GT(withTransactionSize, emptySize);
}

TEST_F(BlockTest, BlockSizeLimitRespected) {
    std::unique_ptr<Block> block = createNormalBlock(1);
    
    // Añadir transacciones hasta alcanzar el límite de tamaño
    // Nota: En la práctica, esto podría ser difícil de alcanzar en testing
    // debido a MAX_TRANSACTIONS, pero probamos la lógica
    
    int addedCount = 0;
    for (int i = 0; i < 100; ++i) { // Número razonable para testing
        Transaction tx = createSignedTransaction(0.001, std::string(100, 'x')); // Transacción con datos grandes
        if (block->addTransaction(tx)) {
            addedCount++;
            
            // Verificar que no excedemos el tamaño máximo
            EXPECT_LE(block->getEstimatedSize(), MAX_BLOCK_SIZE * 1.1); // Con margen del 10%
        } else {
            break;
        }
    }
    
    EXPECT_GT(addedCount, 0); // Deberíamos haber añadido al menos algunas
}

// ============================================================================
// SECCIÓN 8: TESTS DE SERIALIZACIÓN Y RECONSTRUCCIÓN
// ============================================================================

TEST_F(BlockTest, SetHeaderAndTransactions) {
    std::unique_ptr<Block> original = createBlockWithTransactions(1, 3);
    
    // Crear nuevo bloque y establecer header y transacciones
    Block reconstructed;
    reconstructed.setHeader(original->getHeader());
    reconstructed.setTransactions(original->getTransactions());
    
    // Deberían ser equivalentes
    EXPECT_EQ(reconstructed.getHeader().getIndex(), original->getHeader().getIndex());
    EXPECT_EQ(reconstructed.getHeader().getHash(), original->getHeader().getHash());
    EXPECT_EQ(reconstructed.getTransactionCount(), original->getTransactionCount());
    EXPECT_TRUE(reconstructed.isValid());
}

TEST_F(BlockTest, SetTransactionsUpdatesHash) {
    std::unique_ptr<Block> block = createNormalBlock(1);
    std::vector<uint8_t> originalHash = block->getHeader().getHash();
    
    std::vector<Transaction> transactions;
    transactions.push_back(createSignedTransaction(1.0, "new tx"));
    
    block->setTransactions(transactions);
    std::vector<uint8_t> newHash = block->getHeader().getHash();
    
    // El hash debería haber cambiado
    EXPECT_NE(originalHash, newHash);
}

// ============================================================================
// SECCIÓN 9: TESTS DE RENDIMIENTO
// ============================================================================

TEST_F(BlockTest, PerformanceMultipleBlockCreations) {
    const int iterations = 100;
    auto start = std::chrono::high_resolution_clock::now();
    
    std::vector<std::unique_ptr<Block>> blocks;
    blocks.reserve(iterations);
    
    for (int i = 0; i < iterations; ++i) {
        if (i == 0) {
            blocks.push_back(createGenesisBlock());
        } else {
            blocks.push_back(createNormalBlock(i));
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    testMetrics["multiple_block_creations_throughput_ops_per_sec"] = 
        (iterations * 1000.0) / duration.count();
    testMetrics["multiple_block_creations_total"] = iterations;
    
    std::cout << "[PERFORMANCE] Created " << iterations 
              << " blocks in " << duration.count() << "ms" << std::endl;
    
    EXPECT_EQ(blocks.size(), iterations);
    EXPECT_LT(duration.count(), 1000);
}

TEST_F(BlockTest, PerformanceMerkleRootCalculation) {
    const int txCount = 100;
    auto block = createNormalBlock(1);
    
    // Añadir muchas transacciones
    for (int i = 0; i < txCount; ++i) {
        Transaction tx = createSignedTransaction(0.001, "tx " + std::to_string(i));
        EXPECT_TRUE(block->addTransaction(tx));
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    
    std::vector<uint8_t> merkleRoot = block->calculateMerkleRoot();
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    testMetrics["merkle_root_calculation_us"] = duration.count();
    testMetrics["merkle_root_tx_count"] = txCount;
    
    EXPECT_FALSE(merkleRoot.empty());
    EXPECT_LT(duration.count(), 1000000); // Debería ser rápido (< 1 segundo)
}

TEST_F(BlockTest, PerformanceBlockValidation) {
    const int iterations = 50;
    auto block = createBlockWithTransactions(1, 10);
    
    auto start = std::chrono::high_resolution_clock::now();
    
    int validCount = 0;
    for (int i = 0; i < iterations; ++i) {
        if (block->isValid()) {
            validCount++;
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    testMetrics["block_validation_throughput_ops_per_sec"] = 
        (iterations * 1000.0) / duration.count();
    
    EXPECT_EQ(validCount, iterations);
    EXPECT_LT(duration.count(), 1000);
}

// ============================================================================
// SECCIÓN 10: TESTS DE INTEGRACIÓN Y ESCENARIOS COMPLEJOS
// ============================================================================

TEST_F(BlockTest, StressTestLargeBlock) {
    const int targetTxCount = 50; // Número razonable para testing
    auto start = std::chrono::high_resolution_clock::now();
    
    auto block = createNormalBlock(1);
    
    int addedCount = 0;
    for (int i = 0; i < targetTxCount * 2; ++i) { // Intentar más del objetivo
        Transaction tx = createSignedTransaction(0.001, "stress tx " + std::to_string(i));
        if (block->addTransaction(tx)) {
            addedCount++;
        } else {
            break; // Límite alcanzado
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    testMetrics["stress_test_tx_count"] = addedCount;
    testMetrics["stress_test_duration_ms"] = duration.count();
    
    // Verificar que el bloque es válido
    EXPECT_TRUE(block->isValid());
    EXPECT_GT(addedCount, 0);
    
    std::cout << "[STRESS_TEST] Added " << addedCount 
              << " transactions in " << duration.count() << "ms" << std::endl;
}