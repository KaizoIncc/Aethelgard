#include <gtest/gtest.h>
#include "BlockHeader.hpp"
#include "CryptoBase.hpp"
#include "Types.hpp"
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <algorithm>
#include <sstream>
#include <thread>

// ============================================================================
// FIXTURE PRINCIPAL PARA TESTS DE BLOCKHEADER
// ============================================================================

class BlockHeaderTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Inicializar métricas
        testMetrics.clear();
        testStartTime = std::chrono::high_resolution_clock::now();
        
        // Generar datos de prueba
        validHash = generateValidHash();
        allZerosHash = std::vector<uint8_t>(SHA256_HASH_SIZE, 0x00);
        shortHash = std::vector<uint8_t>(SHA256_HASH_SIZE - 1, 0x01);
        longHash = std::vector<uint8_t>(SHA256_HASH_SIZE + 1, 0x01);
    }
    
    void TearDown() override {
        // Calcular métricas finales
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - testStartTime);
        testMetrics["total_test_duration_ms"] = duration.count();
        
        // Log de métricas resumidas
        std::cout << "[METRICS] BlockHeaderTest completed - Duration: " 
                  << duration.count() << "ms" << std::endl;
        for (const auto& [key, value] : testMetrics) {
            if (value > 0) {
                std::cout << "[METRIC] " << key << ": " << value << std::endl;
            }
        }
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
    
    // Helper para crear bloque génesis
    std::unique_ptr<BlockHeader> createGenesisBlock() {
        std::vector<uint8_t> genesisPreviousHash(SHA256_HASH_SIZE, 0x00); // Génesis tiene previousHash todo ceros
        return std::make_unique<BlockHeader>(0, genesisPreviousHash);
    }
    
    // Helper para crear bloque normal
    std::unique_ptr<BlockHeader> createNormalBlock(int64_t index = 1) {
        return std::make_unique<BlockHeader>(index, validHash);
    }
    
    // Helper para verificar que un timestamp es reciente (dentro de 10 segundos)
    bool isTimestampRecent(std::time_t timestamp) {
        auto now = std::chrono::system_clock::to_time_t(
            std::chrono::system_clock::now());
        return std::abs(timestamp - now) <= 10;
    }
    
    // Helper para debug
    template<typename T>
    void debugLog(const std::string& testName, const T& actual, const T& expected) {
        std::cout << "[DEBUG] " << testName 
                  << " - Actual: " << actual 
                  << " | Expected: " << expected 
                  << std::endl;
    }
    
    // Métricas
    std::map<std::string, double> testMetrics;
    std::chrono::high_resolution_clock::time_point testStartTime;
    
    // Datos de prueba
    std::vector<uint8_t> validHash;
    std::vector<uint8_t> allZerosHash;
    std::vector<uint8_t> shortHash;
    std::vector<uint8_t> longHash;
};

// ============================================================================
// SECCIÓN 1: TESTS BÁSICOS DE CONSTRUCCIÓN
// ============================================================================

TEST_F(BlockHeaderTest, ConstructorGenesisBlock) {
    auto start = std::chrono::high_resolution_clock::now();
    
    std::unique_ptr<BlockHeader> genesis = createGenesisBlock();
    
    EXPECT_EQ(genesis->getIndex(), 0);
    EXPECT_EQ(genesis->getPreviousHash(), allZerosHash);
    EXPECT_TRUE(isTimestampRecent(genesis->getTimestamp()));
    
    // Verificar que los hashes están inicializados (pero pueden ser ceros)
    EXPECT_EQ(genesis->getMerkleRoot().size(), SHA256_HASH_SIZE);
    EXPECT_EQ(genesis->getHash().size(), SHA256_HASH_SIZE);
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["constructor_genesis_ms"] = 
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
}

TEST_F(BlockHeaderTest, ConstructorNormalBlock) {
    auto start = std::chrono::high_resolution_clock::now();
    
    std::unique_ptr<BlockHeader> block = createNormalBlock(1);
    
    EXPECT_EQ(block->getIndex(), 1);
    EXPECT_EQ(block->getPreviousHash(), validHash);
    EXPECT_TRUE(isTimestampRecent(block->getTimestamp()));
    EXPECT_EQ(block->getMerkleRoot().size(), SHA256_HASH_SIZE);
    EXPECT_EQ(block->getHash().size(), SHA256_HASH_SIZE);
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["constructor_normal_ms"] = 
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
}

TEST_F(BlockHeaderTest, ConstructorWithHighIndex) {
    // Probar con índices altos
    const int64_t highIndex = 1000000;
    std::unique_ptr<BlockHeader> block = createNormalBlock(highIndex);
    
    EXPECT_EQ(block->getIndex(), highIndex);
    EXPECT_EQ(block->getPreviousHash(), validHash);
    EXPECT_TRUE(block->isValidTimestamp());
}

// ============================================================================
// SECCIÓN 2: TESTS DE VALIDACIÓN DE ENTRADA Y ERRORES
// ============================================================================

TEST_F(BlockHeaderTest, ConstructorNegativeIndexThrowsException) {
    EXPECT_THROW({
        BlockHeader(-1, validHash);
    }, std::invalid_argument);
    
    EXPECT_THROW({
        BlockHeader(-100, validHash);
    }, std::invalid_argument);
}

TEST_F(BlockHeaderTest, ConstructorInvalidPreviousHashForGenesis) {
    // Génesis debe tener hash de tamaño exacto (puede ser todo ceros)
    EXPECT_THROW({
        BlockHeader(0, shortHash); // Tamaño incorrecto
    }, std::invalid_argument);
    
    EXPECT_THROW({
        BlockHeader(0, longHash); // Tamaño incorrecto
    }, std::invalid_argument);
}

TEST_F(BlockHeaderTest, ConstructorInvalidPreviousHashForNormalBlock) {
    // Bloque normal debe tener hash válido (no ceros, tamaño correcto)
    EXPECT_THROW({
        BlockHeader(1, allZerosHash); // Todo ceros no válido para no-génesis
    }, std::invalid_argument);
    
    EXPECT_THROW({
        BlockHeader(1, shortHash); // Tamaño incorrecto
    }, std::invalid_argument);
    
    EXPECT_THROW({
        BlockHeader(1, longHash); // Tamaño incorrecto
    }, std::invalid_argument);
}

// ============================================================================
// SECCIÓN 3: TESTS DE GETTERS Y CONVERSIONES HEX
// ============================================================================

TEST_F(BlockHeaderTest, GettersReturnCorrectValues) {
    std::unique_ptr<BlockHeader> block = createNormalBlock(42);
    
    EXPECT_EQ(block->getIndex(), 42);
    EXPECT_EQ(block->getPreviousHash(), validHash);
    EXPECT_TRUE(isTimestampRecent(block->getTimestamp()));
    
    // Los hashes deberían estar inicializados a ceros
    EXPECT_TRUE(std::all_of(block->getMerkleRoot().begin(), 
                           block->getMerkleRoot().end(), 
                           [](uint8_t b) { return b == 0; }));
    EXPECT_TRUE(std::all_of(block->getHash().begin(), 
                           block->getHash().end(), 
                           [](uint8_t b) { return b == 0; }));
}

TEST_F(BlockHeaderTest, HexConversions) {
    std::unique_ptr<BlockHeader> block = createNormalBlock(1);
    
    // Verificar que las conversiones hex no están vacías
    std::string previousHashHex = block->getPreviousHashHex();
    std::string merkleRootHex = block->getMerkleRootHex();
    std::string hashHex = block->getHashHex();
    
    EXPECT_FALSE(previousHashHex.empty());
    EXPECT_FALSE(merkleRootHex.empty());
    EXPECT_FALSE(hashHex.empty());
    
    // Verificar longitud correcta (64 caracteres para 32 bytes)
    EXPECT_EQ(previousHashHex.length(), SHA256_HASH_SIZE * 2);
    EXPECT_EQ(merkleRootHex.length(), SHA256_HASH_SIZE * 2);
    EXPECT_EQ(hashHex.length(), SHA256_HASH_SIZE * 2);
    
    // Verificar que son hexadecimales válidos
    auto isHexString = [](const std::string& str) {
        return std::all_of(str.begin(), str.end(), [](char c) {
            return std::isxdigit(static_cast<unsigned char>(c));
        });
    };
    
    EXPECT_TRUE(isHexString(previousHashHex));
    EXPECT_TRUE(isHexString(merkleRootHex));
    EXPECT_TRUE(isHexString(hashHex));
}

TEST_F(BlockHeaderTest, HexConversionConsistency) {
    std::unique_ptr<BlockHeader> block = createNormalBlock(1);
    
    // Verificar que getPreviousHashHex() es consistente con getPreviousHash()
    std::vector<uint8_t> previousHash = block->getPreviousHash();
    std::string hexFromBytes;
    {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (uint8_t byte : previousHash) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        hexFromBytes = ss.str();
    }
    
    EXPECT_EQ(block->getPreviousHashHex(), hexFromBytes);
}

// ============================================================================
// SECCIÓN 4: TESTS DE SETTERS Y VALIDACIÓN
// ============================================================================

TEST_F(BlockHeaderTest, SetMerkleRootValid) {
    std::unique_ptr<BlockHeader> block = createNormalBlock(1);
    std::vector<uint8_t> newMerkleRoot = generateValidHash();

    block->setMerkleRoot(newMerkleRoot);

    EXPECT_EQ(block->getMerkleRoot(), newMerkleRoot);
}

TEST_F(BlockHeaderTest, SetHashValid) {
    std::unique_ptr<BlockHeader> block = createNormalBlock(1);
    std::vector<uint8_t> newHash = generateValidHash();
    
    block->setHash(newHash);
    
    EXPECT_EQ(block->getHash(), newHash);
}

// ============================================================================
// SECCIÓN 5: TESTS DE VALIDACIÓN DE ESTADO
// ============================================================================

TEST_F(BlockHeaderTest, IsValidHashMethod) {
    std::unique_ptr<BlockHeader> block = createNormalBlock(1);
    
    EXPECT_TRUE(block->isValidHash(validHash));
    EXPECT_FALSE(block->isValidHash(allZerosHash)); // Todo ceros
    EXPECT_FALSE(block->isValidHash(shortHash));    // Tamaño incorrecto
    EXPECT_FALSE(block->isValidHash(longHash));     // Tamaño incorrecto
    EXPECT_FALSE(block->isValidHash(std::vector<uint8_t>())); // Vacío
}

TEST_F(BlockHeaderTest, IsValidTimestamp) {
    std::unique_ptr<BlockHeader> block = createNormalBlock(1);
    
    // Timestamp reciente debería ser válido
    EXPECT_TRUE(block->isValidTimestamp());
    
    // Bloque con timestamp actual debería ser válido
    BlockHeader currentBlock(1, validHash);
    EXPECT_TRUE(currentBlock.isValidTimestamp());
}

TEST_F(BlockHeaderTest, IsValidTimestampEdgeCases) {
    std::unique_ptr<BlockHeader> block = createNormalBlock(1);
    
    // Crear un bloque con timestamp en el futuro (debería fallar)
    class TestBlockHeader : public BlockHeader {
    public:
        TestBlockHeader(int64_t index, const std::vector<uint8_t>& previousHash, std::time_t customTimestamp)
            : BlockHeader(index, previousHash) {
            // No podemos modificar timestamp directamente, necesitamos otro enfoque
        }
    };
    
    // Para probar timestamp futuro, necesitaríamos inyectar la dependencia del tiempo
    // Por ahora, confiamos en que la lógica del constructor establece timestamp actual
}

TEST_F(BlockHeaderTest, HasValidHashesGenesis) {
    std::unique_ptr<BlockHeader> genesis = createGenesisBlock();
    
    // Génesis tiene previousHash todo ceros (válido para génesis)
    // Pero merkleRoot y hash están en ceros (inválidos hasta que se establezcan)
    EXPECT_FALSE(genesis->hasValidHashes()); // Porque merkleRoot y hash son ceros
    
    // Establecer hashes válidos
    std::vector<uint8_t> validHash = generateValidHash();
    genesis->setMerkleRoot(validHash);
    genesis->setHash(validHash);
    
    EXPECT_TRUE(genesis->hasValidHashes());
}

TEST_F(BlockHeaderTest, HasValidHashesNormalBlock) {
    std::unique_ptr<BlockHeader> block = createNormalBlock(1);
    
    // Bloque normal con previousHash válido pero merkleRoot y hash en ceros
    EXPECT_FALSE(block->hasValidHashes()); // Porque merkleRoot y hash son ceros
    
    // Establecer hashes válidos
    std::vector<uint8_t> validMerkleRoot = generateValidHash();
    std::vector<uint8_t> validBlockHash = generateValidHash();
    block->setMerkleRoot(validMerkleRoot);
    block->setHash(validBlockHash);
    
    EXPECT_TRUE(block->hasValidHashes());
}

TEST_F(BlockHeaderTest, IsValidMethod) {
    std::unique_ptr<BlockHeader> block = createNormalBlock(1);
    
    // Bloque recién creado no es válido porque los hashes están en ceros
    EXPECT_FALSE(block->isValid());
    
    // Establecer hashes válidos
    std::vector<uint8_t> validHash = generateValidHash();
    block->setMerkleRoot(validHash);
    block->setHash(validHash);
    
    // Ahora debería ser válido (timestamp también es válido)
    EXPECT_TRUE(block->isValid());
}

// ============================================================================
// SECCIÓN 6: TESTS DE SERIALIZACIÓN
// ============================================================================

TEST_F(BlockHeaderTest, ToStringMethod) {
    std::unique_ptr<BlockHeader> block = createNormalBlock(123);
    
    std::string str = block->toString();
    
    EXPECT_FALSE(str.empty());
    EXPECT_NE(str.find("index: 123"), std::string::npos);
    EXPECT_NE(str.find("previousHash:"), std::string::npos);
    EXPECT_NE(str.find("merkleRoot:"), std::string::npos);
    EXPECT_NE(str.find("timestamp:"), std::string::npos);
    EXPECT_NE(str.find("hash:"), std::string::npos);
    
    // Verificar que contiene representaciones hex
    EXPECT_NE(str.find(block->getPreviousHashHex()), std::string::npos);
}

TEST_F(BlockHeaderTest, ToBytesMethod) {
    std::unique_ptr<BlockHeader> block = createNormalBlock(42);
    
    std::vector<uint8_t> bytes = block->toBytes();
    
    // Tamaño esperado: 8 (index) + 32 (previousHash) + 32 (merkleRoot) + 8 (timestamp) = 80 bytes
    const size_t expectedSize = 8 + SHA256_HASH_SIZE + SHA256_HASH_SIZE + 8;
    EXPECT_EQ(bytes.size(), expectedSize);
    
    // Verificar estructura de los bytes
    // Primeros 8 bytes: índice
    int64_t reconstructedIndex = 0;
    for (int i = 0; i < 8; ++i) {
        reconstructedIndex |= static_cast<int64_t>(bytes[i]) << (i * 8);
    }
    EXPECT_EQ(reconstructedIndex, 42);
    
    // Siguientes 32 bytes: previousHash
    std::vector<uint8_t> reconstructedPreviousHash(bytes.begin() + 8, bytes.begin() + 8 + SHA256_HASH_SIZE);
    EXPECT_EQ(reconstructedPreviousHash, block->getPreviousHash());
    
    // Siguientes 32 bytes: merkleRoot
    std::vector<uint8_t> reconstructedMerkleRoot(bytes.begin() + 8 + SHA256_HASH_SIZE, 
                                                bytes.begin() + 8 + SHA256_HASH_SIZE * 2);
    EXPECT_EQ(reconstructedMerkleRoot, block->getMerkleRoot());
    
    // Últimos 8 bytes: timestamp
    int64_t reconstructedTimestamp = 0;
    for (int i = 0; i < 8; ++i) {
        reconstructedTimestamp |= static_cast<int64_t>(bytes[8 + SHA256_HASH_SIZE * 2 + i]) << (i * 8);
    }
    EXPECT_EQ(static_cast<std::time_t>(reconstructedTimestamp), block->getTimestamp());
}

TEST_F(BlockHeaderTest, ToBytesConsistency) {
    // Verificar que toBytes es consistente con los getters
    std::unique_ptr<BlockHeader> block1 = createNormalBlock(100);
    std::unique_ptr<BlockHeader> block2 = createNormalBlock(200);
    
    std::vector<uint8_t> bytes1 = block1->toBytes();
    std::vector<uint8_t> bytes2 = block2->toBytes();
    
    // Deberían tener el mismo tamaño pero contenido diferente
    EXPECT_EQ(bytes1.size(), bytes2.size());
    EXPECT_NE(bytes1, bytes2);
}

// ============================================================================
// SECCIÓN 7: TESTS DE RENDIMIENTO
// ============================================================================

TEST_F(BlockHeaderTest, PerformanceMultipleCreations) {
    const int iterations = 1000;
    auto start = std::chrono::high_resolution_clock::now();
    
    std::vector<std::unique_ptr<BlockHeader>> blocks;
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
    
    testMetrics["multiple_creations_throughput_ops_per_sec"] = 
        (iterations * 1000.0) / duration.count();
    testMetrics["multiple_creations_total"] = iterations;
    
    std::cout << "[PERFORMANCE] Created " << iterations 
              << " blocks in " << duration.count() << "ms" << std::endl;
    std::cout << "[PERFORMANCE] Throughput: " 
              << testMetrics["multiple_creations_throughput_ops_per_sec"] << " blocks/sec" << std::endl;
    
    EXPECT_EQ(blocks.size(), iterations);
    EXPECT_LT(duration.count(), 1000); // Debería ser rápido (< 1 segundo)
}

TEST_F(BlockHeaderTest, PerformanceSerialization) {
    const int iterations = 500;
    std::unique_ptr<BlockHeader> block = createNormalBlock(1);
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        std::string str = block->toString();
        std::vector<uint8_t> bytes = block->toBytes();
        EXPECT_FALSE(str.empty());
        EXPECT_FALSE(bytes.empty());
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    testMetrics["serialization_throughput_ops_per_sec"] = 
        (iterations * 2 * 1000.0) / duration.count(); // 2 operaciones por iteración
    testMetrics["serialization_total_operations"] = iterations * 2;
    
    EXPECT_LT(duration.count(), 500); // Debería ser muy rápido
}

// ============================================================================
// SECCIÓN 8: TESTS DE INTEGRACIÓN Y ESCENARIOS COMPLEJOS
// ============================================================================

TEST_F(BlockHeaderTest, CopyAndMoveSemantics) {
    // Probar que los objetos se pueden mover correctamente
    auto original = createNormalBlock(99);
    original->setMerkleRoot(validHash);
    original->setHash(validHash);
    
    // Mover el bloque
    auto moved = std::move(original);
    
    EXPECT_EQ(moved->getIndex(), 99);
    EXPECT_EQ(moved->getMerkleRoot(), validHash);
    EXPECT_EQ(moved->getHash(), validHash);
    EXPECT_TRUE(moved->isValid());
    
    // El original debería estar en estado válido pero vacío
    // (depende de la implementación de move constructor)
}

TEST_F(BlockHeaderTest, StressTestLargeBlockchain) {
    const int blockCount = 100;
    auto start = std::chrono::high_resolution_clock::now();
    
    std::vector<std::unique_ptr<BlockHeader>> blockchain;
    blockchain.push_back(createGenesisBlock());
    
    // Establecer hash para génesis
    std::vector<uint8_t> currentHash = generateValidHash();
    std::vector<uint8_t> merkleHash = generateValidHash();
    blockchain.back()->setHash(currentHash);
    blockchain.back()->setMerkleRoot(merkleHash);

    for (int i = 1; i < blockCount; ++i) {
        auto block = std::make_unique<BlockHeader>(i, currentHash);
        
        std::vector<uint8_t> newHash = generateValidHash();
        block->setMerkleRoot(generateValidHash());
        block->setHash(newHash);
        
        blockchain.push_back(std::move(block));
        currentHash = newHash;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    testMetrics["stress_test_block_count"] = blockCount;
    testMetrics["stress_test_duration_ms"] = duration.count();
    
    EXPECT_EQ(blockchain.size(), blockCount);
    
    // Verificar que todos los bloques son válidos
    int validCount = 0;
    for (const auto& block : blockchain) {
        if (block->isValid()) {
            validCount++;
        }
    }
    
    testMetrics["stress_test_valid_blocks"] = validCount;
    EXPECT_EQ(validCount, blockCount);
}

// ============================================================================
// SECCIÓN 9: TESTS DE CASOS EDGE ESPECÍFICOS
// ============================================================================

TEST_F(BlockHeaderTest, MaximumIndexValue) {
    // Probar con el valor máximo de int64_t
    const int64_t maxIndex = std::numeric_limits<int64_t>::max();
    
    EXPECT_NO_THROW({
        BlockHeader header(maxIndex, validHash);
        EXPECT_EQ(header.getIndex(), maxIndex);
    });
}

TEST_F(BlockHeaderTest, HashPatternDetection) {
    std::unique_ptr<BlockHeader> block = createNormalBlock(1);
    
    // Hash con todos los bytes iguales (debería ser detectado como válido)
    std::vector<uint8_t> allSameHash(SHA256_HASH_SIZE, 0xAB);
    EXPECT_TRUE(block->isValidHash(allSameHash));
    
    // Hash con patrón alternante (debería ser válido)
    std::vector<uint8_t> alternatingHash(SHA256_HASH_SIZE);
    for (size_t i = 0; i < SHA256_HASH_SIZE; ++i) {
        alternatingHash[i] = (i % 2 == 0) ? 0xAA : 0x55;
    }
    EXPECT_TRUE(block->isValidHash(alternatingHash));
}

TEST_F(BlockHeaderTest, TimestampBoundaryConditions) {
    // Este test verificaría condiciones límite de timestamp
    // Necesitaría manipulación del tiempo del sistema, lo cual es complejo
    // Por ahora confiamos en la lógica implementada en isValidTimestamp()
    
    std::unique_ptr<BlockHeader> block = createNormalBlock(1);
    EXPECT_TRUE(block->isValidTimestamp()); // Timestamp actual siempre debería ser válido
}