#include <gtest/gtest.h>
#include "CryptoBase.hpp"
#include "Types.hpp"
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <algorithm>
#include <sstream>
#include <cstring>

// ============================================================================
// FIXTURE PRINCIPAL PARA TESTS DE CRYPTOBASE
// ============================================================================

class CryptoBaseTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Inicializar libsodium una vez para todos los tests
        static bool initialized = false;
        if (!initialized) {
            ASSERT_TRUE(CryptoBase::initialize()) << "Failed to initialize libsodium";
            initialized = true;
        }
        
        // Inicializar métricas
        testMetrics.clear();
        testStartTime = std::chrono::high_resolution_clock::now();
        
        // Datos de prueba comunes
        testData = "Hello, Crypto World!";
        testBinaryData = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
                         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        emptyData = "";
        emptyVector = {};
    }
    
    void TearDown() override {
        // Calcular tiempo total de ejecución
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - testStartTime);
        testMetrics["total_test_duration_ms"] = duration.count();
        
        // Log de métricas resumidas
        std::cout << "[METRICS] CryptoBaseTest completed - Duration: " 
                  << duration.count() << "ms" << std::endl;
        for (const auto& [key, value] : testMetrics) {
            if (value > 0) {
                std::cout << "[METRIC] " << key << ": " << value << std::endl;
            }
        }
    }
    
    // Helper para generar datos aleatorios
    std::vector<uint8_t> generateRandomData(size_t size) {
        std::vector<uint8_t> data(size);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        for (size_t i = 0; i < size; ++i) {
            data[i] = static_cast<uint8_t>(dis(gen));
        }
        return data;
    }
    
    std::string generateRandomString(size_t length) {
        static const char alphanum[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";
        
        std::string result;
        result.reserve(length);
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, sizeof(alphanum) - 2);
        
        for (size_t i = 0; i < length; ++i) {
            result += alphanum[dis(gen)];
        }
        return result;
    }
    
    // Helper para verificar que los datos fueron limpiados
    bool isVectorCleaned(const std::vector<uint8_t>& data) {
        if (data.empty()) return true;
        
        // Verificar que todos los bytes son cero
        return std::all_of(data.begin(), data.end(), [](uint8_t b) { 
            return b == 0; 
        });
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
    std::string testData;
    std::vector<uint8_t> testBinaryData;
    std::string emptyData;
    std::vector<uint8_t> emptyVector;
};

// ============================================================================
// SECCIÓN 1: TESTS BÁSICOS DE HASHING SHA-256
// ============================================================================

TEST_F(CryptoBaseTest, Sha256StringBasic) {
    auto start = std::chrono::high_resolution_clock::now();
    
    std::string hash = CryptoBase::sha256(testData);
    
    // Verificaciones básicas
    EXPECT_FALSE(hash.empty());
    EXPECT_EQ(hash.length(), SHA256_HASH_SIZE * 2); // 64 caracteres hex
    
    // Verificar que es hexadecimal válido
    for (char c : hash) {
        EXPECT_TRUE(std::isxdigit(static_cast<unsigned char>(c)));
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["sha256_string_basic_ms"] = 
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    debugLog("Sha256StringBasic", hash.length(), SHA256_HASH_SIZE * 2);
}

TEST_F(CryptoBaseTest, Sha256VectorBasic) {
    std::vector<uint8_t> hashBytes = CryptoBase::sha256Bytes(testBinaryData);
    
    EXPECT_FALSE(hashBytes.empty());
    EXPECT_EQ(hashBytes.size(), SHA256_HASH_SIZE);
    
    // Verificar que el hash no es todo ceros
    EXPECT_FALSE(std::all_of(hashBytes.begin(), hashBytes.end(), 
                            [](uint8_t b) { return b == 0; }));
}

TEST_F(CryptoBaseTest, Sha256ConsistencyBetweenOverloads) {
    // Verificar que ambas versiones producen el mismo resultado
    std::string hashFromString = CryptoBase::sha256(testData);
    
    std::vector<uint8_t> dataVec(testData.begin(), testData.end());
    std::string hashFromVector = CryptoBase::sha256(dataVec);
    
    EXPECT_EQ(hashFromString, hashFromVector);
}

TEST_F(CryptoBaseTest, Sha256Deterministic) {
    // El mismo input debe producir el mismo hash
    std::string hash1 = CryptoBase::sha256(testData);
    std::string hash2 = CryptoBase::sha256(testData);
    std::string hash3 = CryptoBase::sha256(testData);
    
    EXPECT_EQ(hash1, hash2);
    EXPECT_EQ(hash2, hash3);
}

// ============================================================================
// SECCIÓN 2: TESTS DE CASOS EDGE PARA HASHING
// ============================================================================

TEST_F(CryptoBaseTest, Sha256EmptyInput) {
    // String vacío
    std::string emptyHash = CryptoBase::sha256(emptyData);
    EXPECT_FALSE(emptyHash.empty());
    EXPECT_EQ(emptyHash.length(), SHA256_HASH_SIZE * 2);
    
    // Vector vacío
    std::vector<uint8_t> emptyHashBytes = CryptoBase::sha256Bytes(emptyVector);
    EXPECT_FALSE(emptyHashBytes.empty());
    EXPECT_EQ(emptyHashBytes.size(), SHA256_HASH_SIZE);
    
    // Verificar que el hash del vacío es correcto (hash conocido)
    std::string expectedEmptyHash = 
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    EXPECT_EQ(emptyHash, expectedEmptyHash);
}

TEST_F(CryptoBaseTest, Sha256LargeInput) {
    auto start = std::chrono::high_resolution_clock::now();
    
    // Generar datos grandes (1MB)
    std::vector<uint8_t> largeData = generateRandomData(1024 * 1024);
    std::string largeString(largeData.begin(), largeData.end());
    
    std::vector<uint8_t> hashBytes = CryptoBase::sha256Bytes(largeData);
    std::string hashString = CryptoBase::sha256(largeString);
    
    EXPECT_EQ(hashBytes.size(), SHA256_HASH_SIZE);
    EXPECT_EQ(hashString.length(), SHA256_HASH_SIZE * 2);
    
    // Verificar consistencia
    std::string hashFromBytes = CryptoBase::sha256(largeData);
    EXPECT_EQ(hashString, hashFromBytes);
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["sha256_large_input_ms"] = 
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
}

TEST_F(CryptoBaseTest, Sha256SpecialCharacters) {
    // Test con caracteres especiales y Unicode
    std::vector<std::string> testCases = {
        "Hello, 世界!", // Unicode
        "Line1\nLine2\tTab", // Caracteres de control
        "Null\0Byte", // Byte nulo
        "🎉 Emoji Test 🚀", // Emojis
    };
    
    for (const auto& testCase : testCases) {
        std::string hash = CryptoBase::sha256(testCase);
        EXPECT_FALSE(hash.empty());
        EXPECT_EQ(hash.length(), SHA256_HASH_SIZE * 2);
        
        // Verificar hexadecimal
        for (char c : hash) {
            EXPECT_TRUE(std::isxdigit(static_cast<unsigned char>(c)));
        }
    }
}

// ============================================================================
// SECCIÓN 3: TESTS DE BASE64 ENCODING/DECODING
// ============================================================================

TEST_F(CryptoBaseTest, Base64EncodeDecodeRoundTrip) {
    auto start = std::chrono::high_resolution_clock::now();
    int successCount = 0;
    const int iterations = 50;
    
    for (int i = 0; i < iterations; ++i) {
        std::vector<uint8_t> original = generateRandomData(100 + i * 10);
        std::string encoded = CryptoBase::base64Encode(original);
        
        // Verificar que la codificación no está vacía
        EXPECT_FALSE(encoded.empty());
        
        // Verificar formato base64 básico
        for (char c : encoded) {
            EXPECT_TRUE(std::isalnum(static_cast<unsigned char>(c)) || 
                       c == '+' || c == '/' || c == '=');
        }
        
        // Decodificar y verificar round-trip
        std::vector<uint8_t> decoded = CryptoBase::base64Decode(encoded);
        EXPECT_EQ(original.size(), decoded.size());
        
        if (original.size() == decoded.size()) {
            EXPECT_TRUE(std::equal(original.begin(), original.end(), decoded.begin()));
            ++successCount;
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["base64_roundtrip_success_rate"] = 
        static_cast<double>(successCount) / iterations * 100.0;
    testMetrics["base64_roundtrip_duration_ms"] = 
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    EXPECT_EQ(successCount, iterations);
}

TEST_F(CryptoBaseTest, Base64EmptyData) {
    // Codificar datos vacíos
    std::string encodedEmpty = CryptoBase::base64Encode(emptyVector);
    EXPECT_TRUE(encodedEmpty.empty());
    
    // Decodificar string vacío
    std::vector<uint8_t> decodedEmpty = CryptoBase::base64Decode("");
    EXPECT_TRUE(decodedEmpty.empty());
}

TEST_F(CryptoBaseTest, Base64KnownVectors) {
    // Vectores de prueba conocidos (RFC 4648)
    struct TestCase {
        std::vector<uint8_t> input;
        std::string expected;
    };
    
    std::vector<TestCase> testCases = {
        {{}, ""}, // Vacío
        {{'f'}, "Zg=="},
        {{'f', 'o'}, "Zm8="},
        {{'f', 'o', 'o'}, "Zm9v"},
        {{'f', 'o', 'o', 'b'}, "Zm9vYg=="},
        {{'f', 'o', 'o', 'b', 'a'}, "Zm9vYmE="},
        {{'f', 'o', 'o', 'b', 'a', 'r'}, "Zm9vYmFy"},
    };
    
    for (const auto& testCase : testCases) {
        std::string encoded = CryptoBase::base64Encode(testCase.input);
        EXPECT_EQ(encoded, testCase.expected);
        
        std::vector<uint8_t> decoded = CryptoBase::base64Decode(testCase.expected);
        EXPECT_EQ(decoded, testCase.input);
    }
}

TEST_F(CryptoBaseTest, Base64InvalidInputThrowsException) {
    // Caracteres inválidos en base64
    EXPECT_THROW({
        CryptoBase::base64Decode("!!!invalid!!!");
    }, std::invalid_argument);
    
    EXPECT_THROW({
        CryptoBase::base64Decode("abc$def"); // $ no es base64 válido
    }, std::invalid_argument);
}

// ============================================================================
// SECCIÓN 4: TESTS DE HEX ENCODING/DECODING
// ============================================================================

TEST_F(CryptoBaseTest, HexEncodeDecodeRoundTrip) {
    auto start = std::chrono::high_resolution_clock::now();
    
    std::string hexEncoded = CryptoBase::hexEncode(testBinaryData);
    
    // Verificaciones básicas
    EXPECT_FALSE(hexEncoded.empty());
    EXPECT_EQ(hexEncoded.length(), testBinaryData.size() * 2);
    
    // Verificar que es hexadecimal válido
    for (char c : hexEncoded) {
        EXPECT_TRUE(std::isxdigit(static_cast<unsigned char>(c)));
    }
    
    // Round-trip
    std::vector<uint8_t> decoded = CryptoBase::hexDecode(hexEncoded);
    EXPECT_EQ(testBinaryData.size(), decoded.size());
    EXPECT_TRUE(std::equal(testBinaryData.begin(), testBinaryData.end(), decoded.begin()));
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["hex_roundtrip_ms"] = 
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
}

TEST_F(CryptoBaseTest, HexEmptyData) {
    std::string emptyHex = CryptoBase::hexEncode(emptyVector);
    EXPECT_TRUE(emptyHex.empty());
    
    std::vector<uint8_t> decodedEmpty = CryptoBase::hexDecode("");
    EXPECT_TRUE(decodedEmpty.empty());
}

TEST_F(CryptoBaseTest, HexKnownVectors) {
    struct TestCase {
        std::vector<uint8_t> input;
        std::string expected;
    };
    
    std::vector<TestCase> testCases = {
        {{}, ""},
        {{0x00}, "00"},
        {{0xFF}, "ff"},
        {{0xDE, 0xAD, 0xBE, 0xEF}, "deadbeef"},
        {{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}, "0123456789abcdef"},
    };
    
    for (const auto& testCase : testCases) {
        std::string encoded = CryptoBase::hexEncode(testCase.input);
        EXPECT_EQ(encoded, testCase.expected);
        
        std::vector<uint8_t> decoded = CryptoBase::hexDecode(testCase.expected);
        EXPECT_EQ(decoded, testCase.input);
    }
}

TEST_F(CryptoBaseTest, HexInvalidInputThrowsException) {
    // Longitud impar
    EXPECT_THROW({
        CryptoBase::hexDecode("abc"); // Longitud impar
    }, std::invalid_argument);
    
    // Caracteres no hexadecimales
    EXPECT_THROW({
        CryptoBase::hexDecode("ghijkl"); // 'g' no es hex
    }, std::invalid_argument);
    
    EXPECT_THROW({
        CryptoBase::hexDecode("12!456"); // '!' no es hex
    }, std::invalid_argument);
}

TEST_F(CryptoBaseTest, BytesToHexAlias) {
    // Verificar que bytesToHex es alias de hexEncode
    std::string hex1 = CryptoBase::hexEncode(testBinaryData);
    std::string hex2 = CryptoBase::bytesToHex(testBinaryData);
    
    EXPECT_EQ(hex1, hex2);
}

// ============================================================================
// SECCIÓN 5: TESTS DE SEGURIDAD - SECURE CLEAN
// ============================================================================

TEST_F(CryptoBaseTest, SecureCleanVector) {
    std::vector<uint8_t> sensitiveData = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<uint8_t> originalData = sensitiveData; // Copia
    
    ASSERT_FALSE(sensitiveData.empty());
    ASSERT_FALSE(isVectorCleaned(sensitiveData));
    
    CryptoBase::secureClean(sensitiveData);
    
    // Verificar que los datos fueron limpiados (ceros) pero el vector NO está vacío
    EXPECT_FALSE(sensitiveData.empty());  // El tamaño NO cambia
    EXPECT_TRUE(isVectorCleaned(sensitiveData));  // Pero el contenido sí se limpia
    EXPECT_EQ(sensitiveData.size(), originalData.size());  // Mismo tamaño
}

TEST_F(CryptoBaseTest, SecureCleanString) {
    std::string sensitiveString = "VerySecretPassword123!";
    std::string originalString = sensitiveString; // Copia
    
    ASSERT_FALSE(sensitiveString.empty());
    
    CryptoBase::secureClean(sensitiveString);
    
    // Verificar que el string fue limpiado pero NO está vacío
    EXPECT_FALSE(sensitiveString.empty());  // El tamaño NO cambia
    EXPECT_EQ(sensitiveString.size(), originalString.size());  // Mismo tamaño
    
    // Verificar que todos los caracteres son nulos
    bool allNulls = true;
    for (char c : sensitiveString) {
        if (c != '\0') {
            allNulls = false;
            break;
        }
    }
    EXPECT_TRUE(allNulls);
}

TEST_F(CryptoBaseTest, SecureCleanEmptyContainers) {
    // Limpiar contenedores vacíos no debería causar problemas
    std::vector<uint8_t> emptyVec;
    std::string emptyStr;
    
    CryptoBase::secureClean(emptyVec);
    CryptoBase::secureClean(emptyStr);
    
    EXPECT_TRUE(emptyVec.empty());
    EXPECT_TRUE(emptyStr.empty());
}

TEST_F(CryptoBaseTest, SecureCleanLargeData) {
    // Test con datos grandes para verificar rendimiento
    auto start = std::chrono::high_resolution_clock::now();
    
    std::vector<uint8_t> largeSensitiveData = generateRandomData(1024 * 1024); // 1MB
    std::string largeSensitiveString = generateRandomString(1024 * 1024);
    
    size_t originalDataSize = largeSensitiveData.size();
    size_t originalStringSize = largeSensitiveString.size();
    
    ASSERT_FALSE(largeSensitiveData.empty());
    ASSERT_FALSE(largeSensitiveString.empty());
    
    CryptoBase::secureClean(largeSensitiveData);
    CryptoBase::secureClean(largeSensitiveString);
    
    // Verificar que se limpió el contenido pero NO el tamaño
    EXPECT_FALSE(largeSensitiveData.empty());
    EXPECT_FALSE(largeSensitiveString.empty());
    EXPECT_EQ(largeSensitiveData.size(), originalDataSize);
    EXPECT_EQ(largeSensitiveString.size(), originalStringSize);
    EXPECT_TRUE(isVectorCleaned(largeSensitiveData));
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["secure_clean_large_data_ms"] = 
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
}

// ============================================================================
// SECCIÓN 6: TESTS DE ED25519 HELPERS
// ============================================================================

TEST_F(CryptoBaseTest, Ed25519HelpersWithValidInput) {
    // Solo ejecutar si tenemos datos de prueba válidos para Ed25519
    std::vector<uint8_t> seed(SEED_SIZE, 0x01); // Semilla de prueba
    std::vector<uint8_t> publicKey(PUBLIC_KEY_SIZE);
    std::vector<uint8_t> privateKey(PRIVATE_KEY_SIZE);
    
    // Seed keypair
    EXPECT_TRUE(CryptoBase::ed25519SeedKeypair(publicKey, privateKey, seed));
    
    // Verificar que las claves no son todo ceros
    EXPECT_FALSE(std::all_of(publicKey.begin(), publicKey.end(), 
                            [](uint8_t b) { return b == 0; }));
    EXPECT_FALSE(std::all_of(privateKey.begin(), privateKey.end(), 
                            [](uint8_t b) { return b == 0; }));
    
    // SK to PK
    std::vector<uint8_t> derivedPublicKey(PUBLIC_KEY_SIZE);
    int result = CryptoBase::ed25519SkToPk(derivedPublicKey, privateKey);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(publicKey, derivedPublicKey);
    
    // Limpieza segura
    CryptoBase::secureClean(seed);
    CryptoBase::secureClean(publicKey);
    CryptoBase::secureClean(privateKey);
    CryptoBase::secureClean(derivedPublicKey);
}

TEST_F(CryptoBaseTest, Ed25519HelpersWithInvalidInput) {
    // Semilla de tamaño incorrecto
    std::vector<uint8_t> invalidSeed(16); // Tamaño incorrecto
    std::vector<uint8_t> publicKey(PUBLIC_KEY_SIZE);
    std::vector<uint8_t> privateKey(PRIVATE_KEY_SIZE);
    
    // Esto probablemente fallará en libsodium
    int result = CryptoBase::ed25519SeedKeypair(publicKey, privateKey, invalidSeed);
    // No podemos asumir el resultado, pero verificamos que no hay crash
    
    CryptoBase::secureClean(invalidSeed);
    CryptoBase::secureClean(publicKey);
    CryptoBase::secureClean(privateKey);
}

// ============================================================================
// SECCIÓN 7: TESTS DE RENDIMIENTO Y MÉTRICAS
// ============================================================================

TEST_F(CryptoBaseTest, PerformanceBenchmarkHashing) {
    const int iterations = 1000;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        std::vector<uint8_t> data = generateRandomData(1024); // 1KB por operación
        std::vector<uint8_t> hash = CryptoBase::sha256Bytes(data);
        EXPECT_EQ(hash.size(), SHA256_HASH_SIZE);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    testMetrics["hashing_throughput_ops_per_sec"] = 
        (iterations * 1000.0) / duration.count();
    testMetrics["hashing_total_operations"] = iterations;
    
    std::cout << "[PERFORMANCE] SHA-256: " << iterations 
              << " operations in " << duration.count() << "ms" << std::endl;
    std::cout << "[PERFORMANCE] Throughput: " 
              << testMetrics["hashing_throughput_ops_per_sec"] << " ops/sec" << std::endl;
    
    EXPECT_LT(duration.count(), 5000); // Debería completarse en menos de 5 segundos
}

TEST_F(CryptoBaseTest, PerformanceBenchmarkEncoding) {
    const int iterations = 500;
    std::vector<uint8_t> testData = generateRandomData(512);
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        // Base64 encode/decode
        std::string encoded = CryptoBase::base64Encode(testData);
        std::vector<uint8_t> decoded = CryptoBase::base64Decode(encoded);
        EXPECT_EQ(testData.size(), decoded.size());
        
        // Hex encode/decode
        std::string hex = CryptoBase::hexEncode(testData);
        std::vector<uint8_t> hexDecoded = CryptoBase::hexDecode(hex);
        EXPECT_EQ(testData.size(), hexDecoded.size());
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    testMetrics["encoding_throughput_ops_per_sec"] = 
        (iterations * 2 * 1000.0) / duration.count(); // 2 operaciones por iteración
    testMetrics["encoding_total_operations"] = iterations * 2;
    
    std::cout << "[PERFORMANCE] Encoding: " << iterations * 2 
              << " operations in " << duration.count() << "ms" << std::endl;
}

TEST_F(CryptoBaseTest, MemoryUsageUnderLoad) {
    const int iterations = 100;
    size_t totalMemoryUsed = 0;
    
    for (int i = 0; i < iterations; ++i) {
        std::vector<uint8_t> data = generateRandomData(1024 * 10); // 10KB
        std::string hash = CryptoBase::sha256(data);
        std::string encoded = CryptoBase::base64Encode(data);
        
        totalMemoryUsed += data.size() + hash.size() + encoded.size();
        
        // Limpieza explícita
        CryptoBase::secureClean(data);
    }
    
    testMetrics["memory_usage_total_bytes"] = totalMemoryUsed;
    testMetrics["memory_usage_average_per_op"] = static_cast<double>(totalMemoryUsed) / iterations;
    
    std::cout << "[MEMORY] Total memory used: " << totalMemoryUsed << " bytes" << std::endl;
    std::cout << "[MEMORY] Average per operation: " 
              << testMetrics["memory_usage_average_per_op"] << " bytes" << std::endl;
}

// ============================================================================
// SECCIÓN 8: TESTS DE INTEGRACIÓN Y USO COMBINADO
// ============================================================================

TEST_F(CryptoBaseTest, IntegratedCryptoWorkflow) {
    // Simular un flujo completo de trabajo criptográfico
    auto start = std::chrono::high_resolution_clock::now();
    
    // 1. Datos originales
    std::string originalMessage = "Mensaje secreto para transmisión segura";
    std::vector<uint8_t> messageData(originalMessage.begin(), originalMessage.end());
    
    // 2. Hash de los datos
    std::string messageHash = CryptoBase::sha256(messageData);
    EXPECT_EQ(messageHash.length(), SHA256_HASH_SIZE * 2);
    
    // 3. Codificar datos en base64 para transmisión
    std::string encodedData = CryptoBase::base64Encode(messageData);
    EXPECT_FALSE(encodedData.empty());
    
    // 4. Simular recepción y decodificación
    std::vector<uint8_t> decodedData = CryptoBase::base64Decode(encodedData);
    std::string receivedMessage(decodedData.begin(), decodedData.end());
    
    // 5. Verificar integridad
    std::string receivedHash = CryptoBase::sha256(decodedData);
    EXPECT_EQ(messageHash, receivedHash);
    EXPECT_EQ(originalMessage, receivedMessage);
    
    // 6. Limpieza segura
    CryptoBase::secureClean(messageData);
    CryptoBase::secureClean(decodedData);
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["integrated_workflow_ms"] = 
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    debugLog("IntegratedCryptoWorkflow", originalMessage, receivedMessage);
}

TEST_F(CryptoBaseTest, ConsistencyAcrossMultipleRuns) {
    // Verificar que múltiples ejecuciones son consistentes
    std::vector<std::string> hashes;
    std::vector<std::string> base64Encodings;
    std::vector<std::string> hexEncodings;
    
    const int runs = 10;
    
    for (int i = 0; i < runs; ++i) {
        hashes.push_back(CryptoBase::sha256(testData));
        base64Encodings.push_back(CryptoBase::base64Encode(testBinaryData));
        hexEncodings.push_back(CryptoBase::hexEncode(testBinaryData));
    }
    
    // Todas las ejecuciones deberían producir los mismos resultados
    for (int i = 1; i < runs; ++i) {
        EXPECT_EQ(hashes[0], hashes[i]);
        EXPECT_EQ(base64Encodings[0], base64Encodings[i]);
        EXPECT_EQ(hexEncodings[0], hexEncodings[i]);
    }
    
    testMetrics["consistency_test_runs"] = runs;
}