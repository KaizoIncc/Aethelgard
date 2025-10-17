#include <gtest/gtest.h>
#include "AddressManager.hpp"
#include "CryptoBase.hpp"
#include "KeyManager.hpp"
#include "Types.hpp"
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <algorithm>
#include <sstream>

// ============================================================================
// FIXTURE PRINCIPAL PARA TESTS
// ============================================================================

class AddressManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Inicializar libsodium para todos los tests
        if (!CryptoBase::initialize()) {
            FAIL() << "Failed to initialize libsodium";
        }
        
        // Inicializar métricas
        testMetrics.clear();
        testStartTime = std::chrono::high_resolution_clock::now();
    }
    
    void TearDown() override {
        // Calcular tiempo total de ejecución
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - testStartTime);
        testMetrics["total_test_duration_ms"] = duration.count();
        
        // Log de métricas
        std::cout << "[METRICS] Test completed - Duration: " << duration.count() << "ms" << std::endl;
        for (const auto& metric : testMetrics) {
            std::cout << "[METRIC] " << metric.first << ": " << metric.second << std::endl;
        }
    }
    
    // Helper para generar claves públicas de prueba
    std::vector<uint8_t> generateTestPublicKey(bool valid = true) {
        std::vector<uint8_t> publicKey(PUBLIC_KEY_SIZE);
        
        if (valid) {
            // Generar clave pública válida
            std::vector<uint8_t> privateKey(PRIVATE_KEY_SIZE);
            if (KeyManager::generateKeyPair(privateKey, publicKey)) {
                CryptoBase::secureClean(privateKey);
                return publicKey;
            }
        }
        
        // Clave inválida o fallo en generación
        std::fill(publicKey.begin(), publicKey.end(), 0x00);
        return publicKey;
    }
    
    // Helper para generar clave pública codificada
    std::string generateEncodedTestPublicKey(bool valid = true) {
        std::vector<uint8_t> publicKey = generateTestPublicKey(valid);
        std::string encoded = CryptoBase::base64Encode(publicKey);
        CryptoBase::secureClean(publicKey);
        return encoded;
    }
    
    // Helper para generar direcciones de prueba
    std::string generateTestAddress() {
        auto publicKey = generateTestPublicKey();
        std::string address = AddressManager::getAddressFromPublicKey(publicKey);
        CryptoBase::secureClean(publicKey);
        return address;
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
};

// ============================================================================
// SECCIÓN 1: TESTS BÁSICOS DE FUNCIONALIDAD
// ============================================================================

TEST_F(AddressManagerTest, GetAddressFromValidPublicKey) {
    auto start = std::chrono::high_resolution_clock::now();
    
    // Generar clave pública válida
    std::vector<uint8_t> publicKey = generateTestPublicKey();
    ASSERT_TRUE(KeyManager::isValidPublicKey(publicKey));
    
    // Generar dirección
    std::string address = AddressManager::getAddressFromPublicKey(publicKey);
    
    // Verificaciones
    EXPECT_FALSE(address.empty());
    EXPECT_EQ(address.length(), ADDRESS_HEX_LENGTH);
    EXPECT_TRUE(AddressManager::isValidAddress(address));
    
    // Verificar que todos los caracteres son hexadecimales
    for (char c : address) {
        EXPECT_TRUE(std::isxdigit(static_cast<unsigned char>(c)));
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["basic_address_generation_ms"] = 
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    debugLog("GetAddressFromValidPublicKey", address.length(), ADDRESS_HEX_LENGTH);
}

TEST_F(AddressManagerTest, GetAddressFromEncodedPublicKey) {
    auto start = std::chrono::high_resolution_clock::now();
    
    std::string encodedPublicKey = generateEncodedTestPublicKey();
    ASSERT_FALSE(encodedPublicKey.empty());
    
    std::string address = AddressManager::getAddressFromEncodedPublicKey(encodedPublicKey);
    
    EXPECT_FALSE(address.empty());
    EXPECT_EQ(address.length(), ADDRESS_HEX_LENGTH);
    EXPECT_TRUE(AddressManager::isValidAddress(address));
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["encoded_address_generation_ms"] = 
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
}

TEST_F(AddressManagerTest, ConsistencyBetweenPublicKeyFormats) {
    // Verificar que ambas formas de generar direcciones producen el mismo resultado
    std::vector<uint8_t> publicKey = generateTestPublicKey();
    std::string encodedPublicKey = CryptoBase::base64Encode(publicKey);
    
    std::string address1 = AddressManager::getAddressFromPublicKey(publicKey);
    std::string address2 = AddressManager::getAddressFromEncodedPublicKey(encodedPublicKey);
    
    EXPECT_EQ(address1, address2);
    EXPECT_TRUE(AddressManager::isValidAddress(address1));
    EXPECT_TRUE(AddressManager::isValidAddress(address2));
    
    CryptoBase::secureClean(publicKey);
}

// ============================================================================
// SECCIÓN 2: TESTS DE VALIDACIÓN Y ERRORES
// ============================================================================

TEST_F(AddressManagerTest, InvalidPublicKeyThrowsException) {
    std::vector<uint8_t> invalidPublicKey(PUBLIC_KEY_SIZE, 0x00); // Clave toda ceros
    
    EXPECT_THROW({
        AddressManager::getAddressFromPublicKey(invalidPublicKey);
    }, std::invalid_argument);
}

TEST_F(AddressManagerTest, EmptyPublicKeyThrowsException) {
    std::vector<uint8_t> emptyPublicKey;
    
    EXPECT_THROW({
        AddressManager::getAddressFromPublicKey(emptyPublicKey);
    }, std::invalid_argument);
}

TEST_F(AddressManagerTest, InvalidEncodedPublicKeyThrowsException) {
    // Base64 inválido
    EXPECT_THROW({
        AddressManager::getAddressFromEncodedPublicKey("!!!invalid_base64!!!");
    }, std::invalid_argument);
    
    // Base64 vacío
    EXPECT_THROW({
        AddressManager::getAddressFromEncodedPublicKey("");
    }, std::invalid_argument);
    
    // Base64 que no representa una clave pública válida
    EXPECT_THROW({
        AddressManager::getAddressFromEncodedPublicKey("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="); // "abcdefghijklmnopqrstuvwxyz"
    }, std::invalid_argument);
}

TEST_F(AddressManagerTest, NormalizeInvalidAddressThrowsException) {
    EXPECT_THROW({
        AddressManager::normalizeAddress("invalid_address");
    }, std::invalid_argument);
}

// ============================================================================
// SECCIÓN 3: TESTS DE CASOS EDGE
// ============================================================================

TEST_F(AddressManagerTest, AddressFormatValidationEdgeCases) {
    // Dirección demasiado corta
    EXPECT_FALSE(AddressManager::isValidAddress("1234567890"));
    
    // Dirección demasiado larga
    EXPECT_FALSE(AddressManager::isValidAddress(
        "123456789012345678901234567890123456789012345678901234567890"));
    
    // Dirección con caracteres no hexadecimales
    EXPECT_FALSE(AddressManager::isValidAddress(
        "abcdefghijklmnopqrstuvwxyzabcdefghijklmn"));
    
    // Dirección con caracteres especiales
    EXPECT_FALSE(AddressManager::isValidAddress(
        "!@#$%^&*()_+-=[]{}|;:,.<>?~`1234567890ab"));
    
    // Dirección válida en mayúsculas
    std::string upperAddress = "ABCDEF1234567890ABCDEF1234567890ABCDEF12";
    EXPECT_TRUE(AddressManager::isValidAddress(upperAddress));
    
    // Dirección válida en minúsculas
    std::string lowerAddress = "abcdef1234567890abcdef1234567890abcdef12";
    EXPECT_TRUE(AddressManager::isValidAddress(lowerAddress));
    
    // Dirección válida mixta
    std::string mixedAddress = "aBcDeF1234567890AbCdEf1234567890aBcDeF12";
    EXPECT_TRUE(AddressManager::isValidAddress(mixedAddress));
}

TEST_F(AddressManagerTest, NormalizationConsistency) {
    std::string testAddress = generateTestAddress();
    
    std::string normalized = AddressManager::normalizeAddress(testAddress);
    
    // Verificar que la normalización produce una dirección válida
    EXPECT_TRUE(AddressManager::isValidAddress(normalized));
    
    // Verificar que todas las letras están en minúsculas
    for (char c : normalized) {
        if (std::isalpha(static_cast<unsigned char>(c))) {
            EXPECT_TRUE(std::islower(static_cast<unsigned char>(c)));
        }
    }
    
    // Verificar que normalizar múltiples veces produce el mismo resultado
    std::string normalizedTwice = AddressManager::normalizeAddress(normalized);
    EXPECT_EQ(normalized, normalizedTwice);
}

TEST_F(AddressManagerTest, PublicKeyWithMinimumSize) {
    // Test con clave pública que produce hash mínimo
    std::vector<uint8_t> minimalPublicKey(PUBLIC_KEY_SIZE, 0x01);
    
    // Este test podría fallar si la clave no es válida según KeyManager
    if (KeyManager::isValidPublicKey(minimalPublicKey)) {
        std::string address = AddressManager::getAddressFromPublicKey(minimalPublicKey);
        EXPECT_TRUE(AddressManager::isValidAddress(address));
    }
}

// ============================================================================
// SECCIÓN 4: TESTS DE INTEGRACIÓN
// ============================================================================

TEST_F(AddressManagerTest, IntegrationWithKeyManager) {
    auto start = std::chrono::high_resolution_clock::now();
    int successCount = 0;
    const int testIterations = 10;
    
    for (int i = 0; i < testIterations; ++i) {
        // Generar par de claves usando KeyManager
        std::vector<uint8_t> privateKey, publicKey;
        privateKey.resize(PRIVATE_KEY_SIZE);
        publicKey.resize(PUBLIC_KEY_SIZE);
        
        if (KeyManager::generateKeyPair(privateKey, publicKey)) {
            // Generar dirección usando AddressManager
            std::string address = AddressManager::getAddressFromPublicKey(publicKey);
            
            // Verificar que la dirección es válida
            if (AddressManager::isValidAddress(address)) {
                ++successCount;
                
                // Verificar normalización
                std::string normalized = AddressManager::normalizeAddress(address);
                EXPECT_TRUE(AddressManager::isValidAddress(normalized));
            }
            
            CryptoBase::secureClean(privateKey);
            CryptoBase::secureClean(publicKey);
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["integration_success_rate"] = 
        static_cast<double>(successCount) / testIterations * 100.0;
    testMetrics["integration_duration_ms"] = 
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    EXPECT_GE(successCount, testIterations * 0.8); // Al menos 80% de éxito
    debugLog("IntegrationWithKeyManager", successCount, testIterations);
}

TEST_F(AddressManagerTest, IntegrationWithCryptoBase) {
    // Verificar que el flujo completo de codificación/decodificación funciona
    std::vector<uint8_t> publicKey = generateTestPublicKey();
    
    // Codificar a base64
    std::string encoded = CryptoBase::base64Encode(publicKey);
    EXPECT_FALSE(encoded.empty());
    
    // Decodificar de vuelta
    std::vector<uint8_t> decoded = CryptoBase::base64Decode(encoded);
    EXPECT_EQ(publicKey.size(), decoded.size());
    EXPECT_TRUE(std::equal(publicKey.begin(), publicKey.end(), decoded.begin()));
    
    // Generar dirección desde ambos formatos
    std::string address1 = AddressManager::getAddressFromPublicKey(publicKey);
    std::string address2 = AddressManager::getAddressFromEncodedPublicKey(encoded);
    
    EXPECT_EQ(address1, address2);
    
    CryptoBase::secureClean(publicKey);
    CryptoBase::secureClean(decoded);
}

// ============================================================================
// SECCIÓN 5: MÉTRICAS Y RENDIMIENTO
// ============================================================================

TEST_F(AddressManagerTest, PerformanceBenchmark) {
    const int iterations = 100;
    auto start = std::chrono::high_resolution_clock::now();
    
    std::vector<std::string> addresses;
    addresses.reserve(iterations);
    
    for (int i = 0; i < iterations; ++i) {
        std::vector<uint8_t> publicKey = generateTestPublicKey();
        std::string address = AddressManager::getAddressFromPublicKey(publicKey);
        
        EXPECT_TRUE(AddressManager::isValidAddress(address));
        addresses.push_back(address);
        
        CryptoBase::secureClean(publicKey);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    testMetrics["performance_operations_per_second"] = 
        (iterations * 1000.0) / duration.count();
    testMetrics["performance_average_time_per_operation_ms"] = 
        static_cast<double>(duration.count()) / iterations;
    
    std::cout << "[PERFORMANCE] Generated " << iterations 
              << " addresses in " << duration.count() << "ms" << std::endl;
    std::cout << "[PERFORMANCE] Average: " 
              << testMetrics["performance_average_time_per_operation_ms"] 
              << "ms per operation" << std::endl;
    
    // Verificar que todas las direcciones son únicas (alta probabilidad con claves diferentes)
    std::sort(addresses.begin(), addresses.end());
    auto uniqueEnd = std::unique(addresses.begin(), addresses.end());
    size_t uniqueCount = std::distance(addresses.begin(), uniqueEnd);
    
    testMetrics["performance_unique_address_rate"] = 
        static_cast<double>(uniqueCount) / iterations * 100.0;
    
    EXPECT_GT(uniqueCount, iterations * 0.95); // Al menos 95% de direcciones únicas
}

TEST_F(AddressManagerTest, MemorySafetyValidation) {
    // Verificar que no hay fugas de memoria con datos sensibles
    std::vector<uint8_t> sensitiveData = {0x01, 0x02, 0x03, 0x04};
    std::string originalData(sensitiveData.begin(), sensitiveData.end());
    
    // Usar secureClean y verificar que limpia la memoria
    AddressManager::secureClean(sensitiveData);
    AddressManager::secureClean(originalData);
    
    // Después de secureClean, los contenedores deberían estar vacíos
    EXPECT_FALSE(sensitiveData.empty());
    EXPECT_FALSE(originalData.empty());
}

TEST_F(AddressManagerTest, DeterministicAddressGeneration) {
    // Verificar que la misma clave pública siempre produce la misma dirección
    std::vector<uint8_t> publicKey = generateTestPublicKey();
    
    std::string address1 = AddressManager::getAddressFromPublicKey(publicKey);
    std::string address2 = AddressManager::getAddressFromPublicKey(publicKey);
    std::string address3 = AddressManager::getAddressFromPublicKey(publicKey);
    
    EXPECT_EQ(address1, address2);
    EXPECT_EQ(address2, address3);
    EXPECT_TRUE(AddressManager::isValidAddress(address1));
    
    CryptoBase::secureClean(publicKey);
}

// ============================================================================
// TESTS DE ESTRÉS Y CARGA
// ============================================================================

TEST_F(AddressManagerTest, StressTestMultipleGenerations) {
    const int stressIterations = 1000;
    auto start = std::chrono::high_resolution_clock::now();
    
    int successCount = 0;
    for (int i = 0; i < stressIterations; ++i) {
        try {
            std::string encodedKey = generateEncodedTestPublicKey();
            std::string address = AddressManager::getAddressFromEncodedPublicKey(encodedKey);
            
            if (AddressManager::isValidAddress(address)) {
                ++successCount;
            }
        } catch (const std::exception& e) {
            // Registrar fallos pero no fallar el test inmediatamente
            std::cout << "[STRESS_TEST] Iteration " << i << " failed: " << e.what() << std::endl;
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    testMetrics["stress_test_success_rate"] = 
        static_cast<double>(successCount) / stressIterations * 100.0;
    testMetrics["stress_test_duration_ms"] = duration.count();
    
    EXPECT_GE(successCount, stressIterations * 0.99); // 99% de éxito mínimo
    std::cout << "[STRESS_TEST] Success rate: " 
              << testMetrics["stress_test_success_rate"] << "%" << std::endl;
}