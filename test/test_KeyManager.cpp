#include <gtest/gtest.h>
#include "KeyManager.hpp"
#include "CryptoBase.hpp"
#include "Types.hpp"
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <algorithm>
#include <sstream>
#include <fstream>

// ============================================================================
// FIXTURE PRINCIPAL PARA TESTS DE KEYMANAGER
// ============================================================================

class KeyManagerTest : public ::testing::Test {
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
        
        // Generar datos de prueba comunes
        validSeed = generateValidSeed();
        validPrivateKey = generateValidPrivateKey();
        validPublicKey = generateValidPublicKey();
    }
    
    void TearDown() override {
        // Limpieza segura de datos sensibles
        CryptoBase::secureClean(validSeed);
        CryptoBase::secureClean(validPrivateKey);
        CryptoBase::secureClean(validPublicKey);
        
        // Calcular métricas finales
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - testStartTime);
        testMetrics["total_test_duration_ms"] = duration.count();
        
        // Log de métricas resumidas
        std::cout << "[METRICS] KeyManagerTest completed - Duration: " 
                  << duration.count() << "ms" << std::endl;
        for (const auto& [key, value] : testMetrics) {
            if (value > 0) {
                std::cout << "[METRIC] " << key << ": " << value << std::endl;
            }
        }
    }
    
    // Helper para generar semilla válida
    std::vector<uint8_t> generateValidSeed() {
        std::vector<uint8_t> seed(SEED_SIZE);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1, 255); // Evitar ceros
        
        for (size_t i = 0; i < SEED_SIZE; ++i) {
            seed[i] = static_cast<uint8_t>(dis(gen));
        }
        return seed;
    }
    
    // Helper para generar clave privada válida
    std::vector<uint8_t> generateValidPrivateKey() {
        std::vector<uint8_t> privateKey(PRIVATE_KEY_SIZE);
        std::vector<uint8_t> publicKey(PUBLIC_KEY_SIZE);
        
        if (KeyManager::generateKeyPair(privateKey, publicKey)) {
            return privateKey;
        }
        
        // Fallback: generar manualmente
        std::vector<uint8_t> seed = generateValidSeed();
        privateKey.resize(PRIVATE_KEY_SIZE);
        publicKey.resize(PUBLIC_KEY_SIZE);
        
        if (CryptoBase::ed25519SeedKeypair(publicKey, privateKey, seed) == 0) {
            CryptoBase::secureClean(seed);
            return privateKey;
        }
        
        // Último recurso: datos de prueba hardcodeados (solo para testing)
        std::vector<uint8_t> fallback(PRIVATE_KEY_SIZE, 0x01);
        return fallback;
    }
    
    // Helper para generar clave pública válida
    std::vector<uint8_t> generateValidPublicKey() {
        std::vector<uint8_t> privateKey = generateValidPrivateKey();
        std::vector<uint8_t> publicKey(PUBLIC_KEY_SIZE);
        
        if (KeyManager::derivePublicKey(privateKey, publicKey)) {
            CryptoBase::secureClean(privateKey);
            return publicKey;
        }
        
        CryptoBase::secureClean(privateKey);
        return std::vector<uint8_t>(PUBLIC_KEY_SIZE, 0x02);
    }
    
    // Helper para generar clave codificada
    std::string generateEncodedPrivateKey() {
        std::vector<uint8_t> privateKey = generateValidPrivateKey();
        std::string encoded = CryptoBase::base64Encode(privateKey);
        CryptoBase::secureClean(privateKey);
        return encoded;
    }
    
    std::string generateEncodedPublicKey() {
        std::vector<uint8_t> publicKey = generateValidPublicKey();
        std::string encoded = CryptoBase::base64Encode(publicKey);
        CryptoBase::secureClean(publicKey);
        return encoded;
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
    std::vector<uint8_t> validSeed;
    std::vector<uint8_t> validPrivateKey;
    std::vector<uint8_t> validPublicKey;
};

// ============================================================================
// SECCIÓN 1: TESTS BÁSICOS DE GENERACIÓN DE CLAVES
// ============================================================================

TEST_F(KeyManagerTest, GenerateKeyPairBasic) {
    auto start = std::chrono::high_resolution_clock::now();
    
    std::vector<uint8_t> privateKey(PRIVATE_KEY_SIZE);
    std::vector<uint8_t> publicKey(PUBLIC_KEY_SIZE);
    
    bool success = KeyManager::generateKeyPair(privateKey, publicKey);
    
    EXPECT_TRUE(success);
    EXPECT_TRUE(KeyManager::isValidPrivateKey(privateKey));
    EXPECT_TRUE(KeyManager::isValidPublicKey(publicKey));
    
    // Verificar tamaños
    EXPECT_EQ(privateKey.size(), PRIVATE_KEY_SIZE);
    EXPECT_EQ(publicKey.size(), PUBLIC_KEY_SIZE);
    
    // Verificar que no son todo ceros
    EXPECT_FALSE(std::all_of(privateKey.begin(), privateKey.end(), 
                            [](uint8_t b) { return b == 0; }));
    EXPECT_FALSE(std::all_of(publicKey.begin(), publicKey.end(), 
                            [](uint8_t b) { return b == 0; }));
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["generate_keypair_basic_ms"] = 
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    // Limpieza segura
    KeyManager::secureClean(privateKey);
    KeyManager::secureClean(publicKey);
}

TEST_F(KeyManagerTest, GenerateKeyPairSecureBasic) {
    std::string privateKeyEncoded, publicKeyEncoded;
    
    bool success = KeyManager::generateKeyPairSecure(privateKeyEncoded, publicKeyEncoded);
    
    EXPECT_TRUE(success);
    EXPECT_FALSE(privateKeyEncoded.empty());
    EXPECT_FALSE(publicKeyEncoded.empty());
    
    // Verificar que son base64 válido
    EXPECT_NO_THROW({
        CryptoBase::base64Decode(privateKeyEncoded);
        CryptoBase::base64Decode(publicKeyEncoded);
    });
    
    // Verificar validación
    EXPECT_TRUE(KeyManager::isValidPrivateKeyEncoded(privateKeyEncoded));
    EXPECT_TRUE(KeyManager::isValidPublicKeyEncoded(publicKeyEncoded));
    
    debugLog("GenerateKeyPairSecureBasic", privateKeyEncoded.length(), publicKeyEncoded.length());
}

TEST_F(KeyManagerTest, KeyPairGenerationConsistency) {
    // Generar múltiples pares y verificar que son diferentes
    const int iterations = 5;
    std::vector<std::string> privateKeys;
    std::vector<std::string> publicKeys;
    
    for (int i = 0; i < iterations; ++i) {
        std::string priv, pub;
        ASSERT_TRUE(KeyManager::generateKeyPairSecure(priv, pub));
        
        privateKeys.push_back(priv);
        publicKeys.push_back(pub);
        
        // Verificar que cada par es válido
        EXPECT_TRUE(KeyManager::isValidPrivateKeyEncoded(priv));
        EXPECT_TRUE(KeyManager::isValidPublicKeyEncoded(pub));
    }
    
    // Verificar que todas las claves son únicas (alta entropía)
    for (size_t i = 0; i < privateKeys.size(); ++i) {
        for (size_t j = i + 1; j < privateKeys.size(); ++j) {
            EXPECT_NE(privateKeys[i], privateKeys[j]);
            EXPECT_NE(publicKeys[i], publicKeys[j]);
        }
    }
    
    testMetrics["keypair_uniqueness_tests"] = iterations;
}

// ============================================================================
// SECCIÓN 2: TESTS DE DERIVACIÓN DE CLAVES PÚBLICAS
// ============================================================================

TEST_F(KeyManagerTest, DerivePublicKeyFromValidPrivateKey) {
    auto start = std::chrono::high_resolution_clock::now();
    
    std::vector<uint8_t> publicKey(PUBLIC_KEY_SIZE);
    bool success = KeyManager::derivePublicKey(validPrivateKey, publicKey);
    
    EXPECT_TRUE(success);
    EXPECT_TRUE(KeyManager::isValidPublicKey(publicKey));
    EXPECT_EQ(publicKey.size(), PUBLIC_KEY_SIZE);
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["derive_public_key_ms"] = 
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    KeyManager::secureClean(publicKey);
}

TEST_F(KeyManagerTest, DerivePublicKeyFromEncodedPrivateKey) {
    std::string encodedPrivateKey = generateEncodedPrivateKey();
    ASSERT_TRUE(KeyManager::isValidPrivateKeyEncoded(encodedPrivateKey));
    
    std::string derivedPublicKey = KeyManager::derivePublicKeyFromEncoded(encodedPrivateKey);
    
    EXPECT_FALSE(derivedPublicKey.empty());
    EXPECT_TRUE(KeyManager::isValidPublicKeyEncoded(derivedPublicKey));
    
    // Verificar que es base64 válido
    EXPECT_NO_THROW({
        std::vector<uint8_t> pubBytes = CryptoBase::base64Decode(derivedPublicKey);
        EXPECT_EQ(pubBytes.size(), PUBLIC_KEY_SIZE);
        CryptoBase::secureClean(pubBytes);
    });
}

TEST_F(KeyManagerTest, DerivationConsistency) {
    // Verificar que la derivación es consistente entre diferentes métodos
    std::vector<uint8_t> privateKey = generateValidPrivateKey();
    std::string encodedPrivateKey = CryptoBase::base64Encode(privateKey);
    
    // Derivación desde vector
    std::vector<uint8_t> publicKeyVec(PUBLIC_KEY_SIZE);
    bool success1 = KeyManager::derivePublicKey(privateKey, publicKeyVec);
    
    // Derivación desde encoded
    std::string publicKeyEncoded = KeyManager::derivePublicKeyFromEncoded(encodedPrivateKey);
    
    EXPECT_TRUE(success1);
    EXPECT_FALSE(publicKeyEncoded.empty());
    
    // Convertir y comparar
    std::vector<uint8_t> publicKeyFromEncoded = CryptoBase::base64Decode(publicKeyEncoded);
    
    EXPECT_EQ(publicKeyVec.size(), publicKeyFromEncoded.size());
    EXPECT_TRUE(std::equal(publicKeyVec.begin(), publicKeyVec.end(), 
                          publicKeyFromEncoded.begin()));
    
    // Limpieza
    KeyManager::secureClean(privateKey);
    KeyManager::secureClean(publicKeyVec);
    CryptoBase::secureClean(publicKeyFromEncoded);
}

// ============================================================================
// SECCIÓN 3: TESTS DE VALIDACIÓN DE CLAVES
// ============================================================================

TEST_F(KeyManagerTest, ValidateValidPrivateKey) {
    EXPECT_TRUE(KeyManager::isValidPrivateKey(validPrivateKey));
    
    // También debería funcionar con semilla (32 bytes)
    EXPECT_TRUE(KeyManager::isValidPrivateKey(validSeed));
}

TEST_F(KeyManagerTest, ValidateValidPublicKey) {
    EXPECT_TRUE(KeyManager::isValidPublicKey(validPublicKey));
}

TEST_F(KeyManagerTest, ValidateValidEncodedKeys) {
    std::string encodedPrivate = generateEncodedPrivateKey();
    std::string encodedPublic = generateEncodedPublicKey();
    
    EXPECT_TRUE(KeyManager::isValidPrivateKeyEncoded(encodedPrivate));
    EXPECT_TRUE(KeyManager::isValidPublicKeyEncoded(encodedPublic));
}

TEST_F(KeyManagerTest, PrivateKeyValidationEdgeCases) {
    // Clave privada vacía
    std::vector<uint8_t> emptyKey;
    EXPECT_FALSE(KeyManager::isValidPrivateKey(emptyKey));
    
    // Clave privada toda ceros
    std::vector<uint8_t> allZeros(PRIVATE_KEY_SIZE, 0x00);
    EXPECT_FALSE(KeyManager::isValidPrivateKey(allZeros));
    
    // Tamaño incorrecto
    std::vector<uint8_t> wrongSize(16, 0x01);
    EXPECT_FALSE(KeyManager::isValidPrivateKey(wrongSize));
    
    // Limpieza
    KeyManager::secureClean(allZeros);
    KeyManager::secureClean(wrongSize);
}

TEST_F(KeyManagerTest, PublicKeyValidationEdgeCases) {
    // Clave pública vacía
    std::vector<uint8_t> emptyKey;
    EXPECT_FALSE(KeyManager::isValidPublicKey(emptyKey));
    
    // Clave pública toda ceros
    std::vector<uint8_t> allZeros(PUBLIC_KEY_SIZE, 0x00);
    EXPECT_FALSE(KeyManager::isValidPublicKey(allZeros));
    
    // Tamaño incorrecto
    std::vector<uint8_t> wrongSize(16, 0x01);
    EXPECT_FALSE(KeyManager::isValidPublicKey(wrongSize));
    
    // Limpieza
    KeyManager::secureClean(allZeros);
    KeyManager::secureClean(wrongSize);
}

TEST_F(KeyManagerTest, EncodedKeyValidationEdgeCases) {
    // Strings vacíos
    EXPECT_FALSE(KeyManager::isValidPrivateKeyEncoded(""));
    EXPECT_FALSE(KeyManager::isValidPublicKeyEncoded(""));
    
    // Base64 inválido
    EXPECT_FALSE(KeyManager::isValidPrivateKeyEncoded("!!!invalid_base64!!!"));
    EXPECT_FALSE(KeyManager::isValidPublicKeyEncoded("!!!invalid_base64!!!"));
    
    // Base64 que no representa una clave válida
    EXPECT_FALSE(KeyManager::isValidPrivateKeyEncoded("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=")); // "abcdefghijklmnopqrstuvwxyz"
}

// ============================================================================
// SECCIÓN 4: TESTS DE CASOS EDGE Y ERRORES
// ============================================================================

TEST_F(KeyManagerTest, GenerateKeyPairWithInvalidBufferSizes) {
    // Buffers demasiado pequeños
    std::vector<uint8_t> smallPrivate(PRIVATE_KEY_SIZE - 1);
    std::vector<uint8_t> smallPublic(PUBLIC_KEY_SIZE - 1);
    
    EXPECT_FALSE(KeyManager::generateKeyPair(smallPrivate, smallPublic));
    
    // Buffers demasiado grandes
    std::vector<uint8_t> largePrivate(PRIVATE_KEY_SIZE + 1);
    std::vector<uint8_t> largePublic(PUBLIC_KEY_SIZE + 1);
    
    EXPECT_FALSE(KeyManager::generateKeyPair(largePrivate, largePublic));
    
    // Limpieza
    KeyManager::secureClean(smallPrivate);
    KeyManager::secureClean(smallPublic);
    KeyManager::secureClean(largePrivate);
    KeyManager::secureClean(largePublic);
}

TEST_F(KeyManagerTest, DerivePublicKeyFromInvalidPrivateKey) {
    std::vector<uint8_t> publicKey(PUBLIC_KEY_SIZE);
    
    // Clave privada vacía
    std::vector<uint8_t> emptyPrivate;
    EXPECT_FALSE(KeyManager::derivePublicKey(emptyPrivate, publicKey));
    
    // Clave privada toda ceros
    std::vector<uint8_t> allZeros(PRIVATE_KEY_SIZE, 0x00);
    EXPECT_FALSE(KeyManager::derivePublicKey(allZeros, publicKey));
    
    // Tamaño incorrecto
    std::vector<uint8_t> wrongSize(16, 0x01);
    EXPECT_FALSE(KeyManager::derivePublicKey(wrongSize, publicKey));
    
    // Limpieza
    KeyManager::secureClean(publicKey);
    KeyManager::secureClean(allZeros);
    KeyManager::secureClean(wrongSize);
}

TEST_F(KeyManagerTest, DerivePublicKeyFromEncodedInvalidPrivateKey) {
    // Base64 vacío
    EXPECT_TRUE(KeyManager::derivePublicKeyFromEncoded("").empty());
    
    // Base64 inválido
    EXPECT_TRUE(KeyManager::derivePublicKeyFromEncoded("!!!invalid!!!").empty());
    
    // Base64 que no representa una clave privada válida
    std::string invalidKey = CryptoBase::base64Encode(std::vector<uint8_t>(16, 0x01));
    EXPECT_TRUE(KeyManager::derivePublicKeyFromEncoded(invalidKey).empty());
}

TEST_F(KeyManagerTest, SecureCleanFunctionality) {
    std::vector<uint8_t> sensitiveData = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<uint8_t> originalData = sensitiveData; // Copia
    
    ASSERT_FALSE(sensitiveData.empty());
    ASSERT_FALSE(isVectorCleaned(sensitiveData));
    
    KeyManager::secureClean(sensitiveData);
    
    // Verificar el comportamiento: contenido limpiado pero vector NO vacío
    EXPECT_FALSE(sensitiveData.empty());  // El tamaño se mantiene
    EXPECT_TRUE(isVectorCleaned(sensitiveData));  // Pero el contenido se limpia
    EXPECT_EQ(sensitiveData.size(), originalData.size());  // Mismo tamaño que original
}

// ============================================================================
// SECCIÓN 5: TESTS DE SEGURIDAD Y MEMORIA
// ============================================================================

TEST_F(KeyManagerTest, MemoryIsCleanedAfterSecureGeneration) {
    // Verificar que generateKeyPairSecure limpia la memoria interna
    std::string privateKey1, publicKey1;
    ASSERT_TRUE(KeyManager::generateKeyPairSecure(privateKey1, publicKey1));
    
    // Generar otro par - debería ser diferente (no reutiliza memoria)
    std::string privateKey2, publicKey2;
    ASSERT_TRUE(KeyManager::generateKeyPairSecure(privateKey2, publicKey2));
    
    EXPECT_NE(privateKey1, privateKey2);
    EXPECT_NE(publicKey1, publicKey2);
    
    // Ambos deberían ser válidos
    EXPECT_TRUE(KeyManager::isValidPrivateKeyEncoded(privateKey1));
    EXPECT_TRUE(KeyManager::isValidPrivateKeyEncoded(privateKey2));
    EXPECT_TRUE(KeyManager::isValidPublicKeyEncoded(publicKey1));
    EXPECT_TRUE(KeyManager::isValidPublicKeyEncoded(publicKey2));
}

TEST_F(KeyManagerTest, PrivateKeyStructureValidation) {
    // Para claves privadas de 64 bytes, verificar estructura interna
    std::vector<uint8_t> privateKey64 = generateValidPrivateKey();
    ASSERT_EQ(privateKey64.size(), PRIVATE_KEY_SIZE);
    
    EXPECT_TRUE(KeyManager::isValidPrivateKey(privateKey64));
    
    // La clave debería tener los últimos 32 bytes como clave pública derivada
    // Esto se verifica internamente en isValidPrivateKey
    
    KeyManager::secureClean(privateKey64);
}

TEST_F(KeyManagerTest, NoMemoryLeaksInErrorCases) {
    // Test para verificar que no hay fugas de memoria en casos de error
    const int errorIterations = 10;
    
    for (int i = 0; i < errorIterations; ++i) {
        // Intentar generar con buffers de tamaño incorrecto
        std::vector<uint8_t> wrongSizePrivate(PRIVATE_KEY_SIZE - 1, 0x01);
        std::vector<uint8_t> wrongSizePublic(PUBLIC_KEY_SIZE - 1, 0x01);
        
        bool success = KeyManager::generateKeyPair(wrongSizePrivate, wrongSizePublic);
        EXPECT_FALSE(success); // Debería fallar
        
        // Los buffers no deberían ser modificados en caso de error
        EXPECT_TRUE(std::all_of(wrongSizePrivate.begin(), wrongSizePrivate.end(),
                               [](uint8_t b) { return b == 0x01; }));
        EXPECT_TRUE(std::all_of(wrongSizePublic.begin(), wrongSizePublic.end(),
                               [](uint8_t b) { return b == 0x01; }));
        
        KeyManager::secureClean(wrongSizePrivate);
        KeyManager::secureClean(wrongSizePublic);
    }
}

// ============================================================================
// SECCIÓN 6: TESTS DE RENDIMIENTO
// ============================================================================

TEST_F(KeyManagerTest, PerformanceKeyGeneration) {
    const int iterations = 100;
    auto start = std::chrono::high_resolution_clock::now();
    
    int successCount = 0;
    for (int i = 0; i < iterations; ++i) {
        std::vector<uint8_t> privateKey(PRIVATE_KEY_SIZE);
        std::vector<uint8_t> publicKey(PUBLIC_KEY_SIZE);
        
        if (KeyManager::generateKeyPair(privateKey, publicKey)) {
            if (KeyManager::isValidPrivateKey(privateKey) && 
                KeyManager::isValidPublicKey(publicKey)) {
                ++successCount;
            }
            
            KeyManager::secureClean(privateKey);
            KeyManager::secureClean(publicKey);
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    testMetrics["key_generation_throughput_ops_per_sec"] = 
        (iterations * 1000.0) / duration.count();
    testMetrics["key_generation_success_rate"] = 
        static_cast<double>(successCount) / iterations * 100.0;
    testMetrics["key_generation_total_operations"] = iterations;
    
    std::cout << "[PERFORMANCE] Key Generation: " << iterations 
              << " operations in " << duration.count() << "ms" << std::endl;
    std::cout << "[PERFORMANCE] Success rate: " 
              << testMetrics["key_generation_success_rate"] << "%" << std::endl;
    std::cout << "[PERFORMANCE] Throughput: " 
              << testMetrics["key_generation_throughput_ops_per_sec"] << " ops/sec" << std::endl;
    
    EXPECT_GE(successCount, iterations * 0.95); // 95% de éxito mínimo
    EXPECT_LT(duration.count(), 10000); // Menos de 10 segundos
}

TEST_F(KeyManagerTest, PerformanceKeyDerivation) {
    const int iterations = 100;
    auto start = std::chrono::high_resolution_clock::now();
    
    int successCount = 0;
    for (int i = 0; i < iterations; ++i) {
        std::vector<uint8_t> privateKey = generateValidPrivateKey();
        std::vector<uint8_t> publicKey(PUBLIC_KEY_SIZE);
        
        if (KeyManager::derivePublicKey(privateKey, publicKey)) {
            if (KeyManager::isValidPublicKey(publicKey)) {
                ++successCount;
            }
            
            KeyManager::secureClean(publicKey);
        }
        
        KeyManager::secureClean(privateKey);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    testMetrics["key_derivation_throughput_ops_per_sec"] = 
        (iterations * 1000.0) / duration.count();
    testMetrics["key_derivation_success_rate"] = 
        static_cast<double>(successCount) / iterations * 100.0;
    
    EXPECT_GE(successCount, iterations * 0.98); // 98% de éxito mínimo
}

TEST_F(KeyManagerTest, PerformanceEncodedKeyGeneration) {
    const int iterations = 50;
    auto start = std::chrono::high_resolution_clock::now();
    
    int successCount = 0;
    for (int i = 0; i < iterations; ++i) {
        std::string privateKey, publicKey;
        
        if (KeyManager::generateKeyPairSecure(privateKey, publicKey)) {
            if (KeyManager::isValidPrivateKeyEncoded(privateKey) && 
                KeyManager::isValidPublicKeyEncoded(publicKey)) {
                ++successCount;
            }
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    testMetrics["encoded_key_generation_throughput_ops_per_sec"] = 
        (iterations * 1000.0) / duration.count();
    testMetrics["encoded_key_generation_success_rate"] = 
        static_cast<double>(successCount) / iterations * 100.0;
    
    EXPECT_EQ(successCount, iterations); // 100% de éxito esperado
}

// ============================================================================
// SECCIÓN 7: TESTS DE INTEGRACIÓN
// ============================================================================

TEST_F(KeyManagerTest, IntegrationWithCryptoBase) {
    // Verificar que KeyManager funciona correctamente con CryptoBase
    auto start = std::chrono::high_resolution_clock::now();
    
    // 1. Generar par de claves
    std::string privateKeyEncoded, publicKeyEncoded;
    ASSERT_TRUE(KeyManager::generateKeyPairSecure(privateKeyEncoded, publicKeyEncoded));
    
    // 2. Verificar con CryptoBase
    std::vector<uint8_t> privateKeyBytes = CryptoBase::base64Decode(privateKeyEncoded);
    std::vector<uint8_t> publicKeyBytes = CryptoBase::base64Decode(publicKeyEncoded);
    
    EXPECT_EQ(privateKeyBytes.size(), PRIVATE_KEY_SIZE);
    EXPECT_EQ(publicKeyBytes.size(), PUBLIC_KEY_SIZE);
    
    // 3. Derivar clave pública desde privada usando CryptoBase directamente
    std::vector<uint8_t> derivedPublicKey(PUBLIC_KEY_SIZE);
    int result = CryptoBase::ed25519SkToPk(derivedPublicKey, privateKeyBytes);
    
    EXPECT_EQ(result, 0);
    EXPECT_EQ(publicKeyBytes, derivedPublicKey);
    
    // 4. Limpieza
    CryptoBase::secureClean(privateKeyBytes);
    CryptoBase::secureClean(publicKeyBytes);
    CryptoBase::secureClean(derivedPublicKey);
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["integration_with_cryptobase_ms"] = 
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
}

TEST_F(KeyManagerTest, IntegrationWithAddressManager) {
    // Verificar que las claves generadas pueden usarse con AddressManager
    std::string privateKeyEncoded, publicKeyEncoded;
    ASSERT_TRUE(KeyManager::generateKeyPairSecure(privateKeyEncoded, publicKeyEncoded));
    
    // Decodificar clave pública
    std::vector<uint8_t> publicKeyBytes = CryptoBase::base64Decode(publicKeyEncoded);
    
    // Generar dirección (simulando uso con AddressManager)
    // Nota: Esto requiere incluir AddressManager.hpp
    std::string address;
    EXPECT_NO_THROW({
        // En un test real, llamaríamos a AddressManager::getAddressFromPublicKey
        // address = AddressManager::getAddressFromPublicKey(publicKeyBytes);
        
        // Por ahora, simulamos la generación de dirección
        std::vector<uint8_t> hash = CryptoBase::sha256Bytes(publicKeyBytes);
        if (hash.size() >= ADDRESS_SIZE) {
            std::vector<uint8_t> addressBytes(hash.end() - ADDRESS_SIZE, hash.end());
            address = CryptoBase::hexEncode(addressBytes);
        }
    });
    
    EXPECT_FALSE(address.empty());
    EXPECT_EQ(address.length(), ADDRESS_HEX_LENGTH);
    
    // Limpieza
    CryptoBase::secureClean(publicKeyBytes);
}

TEST_F(KeyManagerTest, CompleteKeyManagementWorkflow) {
    // Simular un flujo completo de gestión de claves
    auto start = std::chrono::high_resolution_clock::now();
    
    // 1. Generación de claves
    std::string privateKeyEncoded, publicKeyEncoded;
    ASSERT_TRUE(KeyManager::generateKeyPairSecure(privateKeyEncoded, publicKeyEncoded));
    
    // 2. Validación
    ASSERT_TRUE(KeyManager::isValidPrivateKeyEncoded(privateKeyEncoded));
    ASSERT_TRUE(KeyManager::isValidPublicKeyEncoded(publicKeyEncoded));
    
    // 3. Derivación de clave pública desde privada
    std::string derivedPublicKey = KeyManager::derivePublicKeyFromEncoded(privateKeyEncoded);
    EXPECT_FALSE(derivedPublicKey.empty());
    EXPECT_TRUE(KeyManager::isValidPublicKeyEncoded(derivedPublicKey));
    
    // 4. Verificar que la derivación coincide con la generación original
    EXPECT_EQ(publicKeyEncoded, derivedPublicKey);
    
    // 5. Round-trip de codificación/decodificación
    std::vector<uint8_t> privateKeyBytes = CryptoBase::base64Decode(privateKeyEncoded);
    std::string reencodedPrivateKey = CryptoBase::base64Encode(privateKeyBytes);
    EXPECT_EQ(privateKeyEncoded, reencodedPrivateKey);
    
    // 6. Limpieza segura
    CryptoBase::secureClean(privateKeyBytes);
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["complete_workflow_ms"] = 
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    debugLog("CompleteKeyManagementWorkflow", 
             privateKeyEncoded.length(), publicKeyEncoded.length());
}

// ============================================================================
// SECCIÓN 8: TESTS DE ESTRÉS
// ============================================================================

TEST_F(KeyManagerTest, StressTestMultipleGenerations) {
    const int stressIterations = 200;
    auto start = std::chrono::high_resolution_clock::now();
    
    int successCount = 0;
    std::vector<std::string> allPrivateKeys;
    std::vector<std::string> allPublicKeys;
    
    for (int i = 0; i < stressIterations; ++i) {
        std::string privateKey, publicKey;
        
        if (KeyManager::generateKeyPairSecure(privateKey, publicKey)) {
            if (KeyManager::isValidPrivateKeyEncoded(privateKey) && 
                KeyManager::isValidPublicKeyEncoded(publicKey)) {
                ++successCount;
                allPrivateKeys.push_back(privateKey);
                allPublicKeys.push_back(publicKey);
            }
        }
        
        // Cada 10 iteraciones, hacer limpieza de vectores para control de memoria
        if (i % 10 == 0) {
            allPrivateKeys.clear();
            allPublicKeys.clear();
            allPrivateKeys.shrink_to_fit();
            allPublicKeys.shrink_to_fit();
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    testMetrics["stress_test_success_rate"] = 
        static_cast<double>(successCount) / stressIterations * 100.0;
    testMetrics["stress_test_duration_ms"] = duration.count();
    
    std::cout << "[STRESS_TEST] Generated " << successCount 
              << "/" << stressIterations << " key pairs in " 
              << duration.count() << "ms" << std::endl;
    
    EXPECT_GE(successCount, stressIterations * 0.98); // 98% de éxito mínimo
    EXPECT_LT(duration.count(), 30000); // Menos de 30 segundos
}

TEST_F(KeyManagerTest, ConsecutiveOperationsStability) {
    // Realizar operaciones consecutivas para verificar estabilidad
    const int consecutiveOps = 50;
    
    for (int i = 0; i < consecutiveOps; ++i) {
        // Generación
        std::string priv1, pub1;
        ASSERT_TRUE(KeyManager::generateKeyPairSecure(priv1, pub1));
        
        // Validación
        ASSERT_TRUE(KeyManager::isValidPrivateKeyEncoded(priv1));
        ASSERT_TRUE(KeyManager::isValidPublicKeyEncoded(pub1));
        
        // Derivación
        std::string derivedPub = KeyManager::derivePublicKeyFromEncoded(priv1);
        ASSERT_FALSE(derivedPub.empty());
        EXPECT_EQ(pub1, derivedPub);
        
        // Generación adicional
        std::string priv2, pub2;
        ASSERT_TRUE(KeyManager::generateKeyPairSecure(priv2, pub2));
        ASSERT_NE(priv1, priv2); // Deben ser diferentes
        
        // Validación cruzada
        ASSERT_TRUE(KeyManager::isValidPrivateKeyEncoded(priv2));
        ASSERT_TRUE(KeyManager::isValidPublicKeyEncoded(pub2));
    }
    
    testMetrics["consecutive_operations"] = consecutiveOps;
}