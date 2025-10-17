#include <gtest/gtest.h>
#include "SignatureManager.hpp"
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
// FIXTURE PRINCIPAL PARA TESTS DE SIGNATUREMANAGER
// ============================================================================

class SignatureManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Inicializar SignatureManager (que inicializa CryptoBase)
        ASSERT_TRUE(SignatureManager::initialize()) << "Failed to initialize SignatureManager";
        
        // Inicializar métricas
        testMetrics.clear();
        testStartTime = std::chrono::high_resolution_clock::now();
        
        // Generar datos de prueba
        generateTestData();
    }
    
    void TearDown() override {
        // Limpieza segura de datos sensibles
        CryptoBase::secureClean(testPrivateKey);
        CryptoBase::secureClean(testPublicKey);
        CryptoBase::secureClean(testMessage);
        CryptoBase::secureClean(testSignature);
        
        // Calcular métricas finales
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - testStartTime);
        testMetrics["total_test_duration_ms"] = duration.count();
        
        // Log de métricas resumidas
        std::cout << "[METRICS] SignatureManagerTest completed - Duration: " 
                  << duration.count() << "ms" << std::endl;
        for (const auto& [key, value] : testMetrics) {
            if (value > 0) {
                std::cout << "[METRIC] " << key << ": " << value << std::endl;
            }
        }
    }
    
    void generateTestData() {
        // Generar par de claves
        testPrivateKey.resize(PRIVATE_KEY_SIZE);
        testPublicKey.resize(PUBLIC_KEY_SIZE);
        ASSERT_TRUE(KeyManager::generateKeyPair(testPrivateKey, testPublicKey));
        
        // Generar mensaje de prueba
        testMessage = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21}; // "Hello, World!"
        
        // Generar firma de prueba
        testSignature.resize(SIGNATURE_SIZE);
        ASSERT_TRUE(SignatureManager::signMessage(testPrivateKey, testMessage, testSignature));
        
        // Generar versiones codificadas
        encodedPrivateKey = CryptoBase::base64Encode(testPrivateKey);
        encodedPublicKey = CryptoBase::base64Encode(testPublicKey);
        encodedSignature = CryptoBase::base64Encode(testSignature);
    }
    
    // Helper para generar mensajes aleatorios
    std::vector<uint8_t> generateRandomMessage(size_t size = 128) {
        std::vector<uint8_t> message(size);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1, 255);
        
        for (size_t i = 0; i < size; ++i) {
            message[i] = static_cast<uint8_t>(dis(gen));
        }
        return message;
    }
    
    std::string generateRandomString(size_t length = 64) {
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
    
    // Helper para debug
    template<typename T>
    void debugLog(const std::string& testName, const T& actual, const T& expected) {
        std::cout << "[DEBUG] " << testName 
                  << " - Actual: " << actual 
                  << " | Expected: " << expected 
                  << std::endl;
    }

    // Helper para verificar que los datos fueron limpiados
    bool isVectorCleaned(const std::vector<uint8_t>& data) {
        if (data.empty()) return true;
        
        // Verificar que todos los bytes son cero
        return std::all_of(data.begin(), data.end(), [](uint8_t b) { 
            return b == 0; 
        });
    }
    
    // Métricas
    std::map<std::string, double> testMetrics;
    std::chrono::high_resolution_clock::time_point testStartTime;
    
    // Datos de prueba
    std::vector<uint8_t> testPrivateKey;
    std::vector<uint8_t> testPublicKey;
    std::vector<uint8_t> testMessage;
    std::vector<uint8_t> testSignature;
    std::string encodedPrivateKey;
    std::string encodedPublicKey;
    std::string encodedSignature;
};

// ============================================================================
// SECCIÓN 1: TESTS BÁSICOS DE INICIALIZACIÓN Y FIRMA
// ============================================================================

TEST_F(SignatureManagerTest, InitializeSuccess) {
    // La inicialización ya se hizo en SetUp, verificar que fue exitosa
    EXPECT_TRUE(SignatureManager::initialize()); // Debería ser idempotente
    
    // Verificar que podemos realizar operaciones básicas
    std::vector<uint8_t> signature(SIGNATURE_SIZE);
    bool success = SignatureManager::signMessage(testPrivateKey, testMessage, signature);
    EXPECT_TRUE(success);
    
    SignatureManager::secureClean(signature);
}

TEST_F(SignatureManagerTest, SignMessageBasic) {
    auto start = std::chrono::high_resolution_clock::now();
    
    std::vector<uint8_t> signature(SIGNATURE_SIZE);
    bool success = SignatureManager::signMessage(testPrivateKey, testMessage, signature);
    
    EXPECT_TRUE(success);
    EXPECT_TRUE(SignatureManager::isValidSignature(signature));
    EXPECT_EQ(signature.size(), SIGNATURE_SIZE);
    
    // Verificar que no es todo ceros
    EXPECT_FALSE(std::all_of(signature.begin(), signature.end(), 
                            [](uint8_t b) { return b == 0; }));
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["sign_message_basic_ms"] = 
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    SignatureManager::secureClean(signature);
}

TEST_F(SignatureManagerTest, SignMessageEncodedBasic) {
    std::string signatureBase64 = SignatureManager::signMessageEncoded(encodedPrivateKey, testMessage);
    
    EXPECT_FALSE(signatureBase64.empty());
    EXPECT_TRUE(SignatureManager::isValidSignatureEncoded(signatureBase64));
    
    // Verificar que es base64 válido
    EXPECT_NO_THROW({
        std::vector<uint8_t> signatureBytes = CryptoBase::base64Decode(signatureBase64);
        EXPECT_EQ(signatureBytes.size(), SIGNATURE_SIZE);
        SignatureManager::secureClean(signatureBytes);
    });
}

TEST_F(SignatureManagerTest, VerifySignatureBasic) {
    auto start = std::chrono::high_resolution_clock::now();
    
    bool isValid = SignatureManager::verifySignature(testPublicKey, testMessage, testSignature);
    
    EXPECT_TRUE(isValid);
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["verify_signature_basic_ms"] = 
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
}

TEST_F(SignatureManagerTest, VerifySignatureEncodedBasic) {
    bool isValid = SignatureManager::verifySignatureEncoded(encodedPublicKey, testMessage, encodedSignature);
    
    EXPECT_TRUE(isValid);
}

// ============================================================================
// SECCIÓN 2: TESTS DE VALIDACIÓN Y VERIFICACIÓN
// ============================================================================

TEST_F(SignatureManagerTest, SignatureVerificationRoundTrip) {
    // Firmar un mensaje y luego verificar la firma
    std::vector<uint8_t> customMessage = generateRandomMessage(256);
    std::vector<uint8_t> signature(SIGNATURE_SIZE);
    
    // Firmar
    ASSERT_TRUE(SignatureManager::signMessage(testPrivateKey, customMessage, signature));
    ASSERT_TRUE(SignatureManager::isValidSignature(signature));
    
    // Verificar
    bool isValid = SignatureManager::verifySignature(testPublicKey, customMessage, signature);
    EXPECT_TRUE(isValid);
    
    // Verificar con versión codificada
    std::string encodedSig = CryptoBase::base64Encode(signature);
    bool isValidEncoded = SignatureManager::verifySignatureEncoded(encodedPublicKey, customMessage, encodedSig);
    EXPECT_TRUE(isValidEncoded);
    
    SignatureManager::secureClean(signature);
    CryptoBase::secureClean(customMessage);
}

TEST_F(SignatureManagerTest, SignatureConsistency) {
    // La misma clave y mensaje debería producir la misma firma
    std::vector<uint8_t> signature1(SIGNATURE_SIZE);
    std::vector<uint8_t> signature2(SIGNATURE_SIZE);
    std::vector<uint8_t> signature3(SIGNATURE_SIZE);
    
    ASSERT_TRUE(SignatureManager::signMessage(testPrivateKey, testMessage, signature1));
    ASSERT_TRUE(SignatureManager::signMessage(testPrivateKey, testMessage, signature2));
    ASSERT_TRUE(SignatureManager::signMessage(testPrivateKey, testMessage, signature3));
    
    // Las firmas deberían ser idénticas (firma determinística)
    EXPECT_EQ(signature1, signature2);
    EXPECT_EQ(signature2, signature3);
    
    SignatureManager::secureClean(signature1);
    SignatureManager::secureClean(signature2);
    SignatureManager::secureClean(signature3);
}

TEST_F(SignatureManagerTest, DifferentMessagesProduceDifferentSignatures) {
    std::vector<uint8_t> message1 = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
    std::vector<uint8_t> message2 = {0x57, 0x6F, 0x72, 0x6C, 0x64}; // "World"
    
    std::vector<uint8_t> signature1(SIGNATURE_SIZE);
    std::vector<uint8_t> signature2(SIGNATURE_SIZE);
    
    ASSERT_TRUE(SignatureManager::signMessage(testPrivateKey, message1, signature1));
    ASSERT_TRUE(SignatureManager::signMessage(testPrivateKey, message2, signature2));
    
    // Las firmas deberían ser diferentes para mensajes diferentes
    EXPECT_NE(signature1, signature2);
    
    SignatureManager::secureClean(signature1);
    SignatureManager::secureClean(signature2);
    CryptoBase::secureClean(message1);
    CryptoBase::secureClean(message2);
}

TEST_F(SignatureManagerTest, DifferentKeysProduceDifferentSignatures) {
    // Generar otro par de claves
    std::vector<uint8_t> privateKey2(PRIVATE_KEY_SIZE);
    std::vector<uint8_t> publicKey2(PUBLIC_KEY_SIZE);
    ASSERT_TRUE(KeyManager::generateKeyPair(privateKey2, publicKey2));
    
    std::vector<uint8_t> signature1(SIGNATURE_SIZE);
    std::vector<uint8_t> signature2(SIGNATURE_SIZE);
    
    ASSERT_TRUE(SignatureManager::signMessage(testPrivateKey, testMessage, signature1));
    ASSERT_TRUE(SignatureManager::signMessage(privateKey2, testMessage, signature2));
    
    // Las firmas deberían ser diferentes para claves diferentes
    EXPECT_NE(signature1, signature2);
    
    SignatureManager::secureClean(signature1);
    SignatureManager::secureClean(signature2);
    SignatureManager::secureClean(privateKey2);
    SignatureManager::secureClean(publicKey2);
}

// ============================================================================
// SECCIÓN 3: TESTS DE VALIDACIÓN DE ENTRADA Y ERRORES
// ============================================================================

TEST_F(SignatureManagerTest, SignWithInvalidPrivateKey) {
    std::vector<uint8_t> signature(SIGNATURE_SIZE);
    
    // Clave privada vacía
    std::vector<uint8_t> emptyPrivateKey;
    EXPECT_FALSE(SignatureManager::signMessage(emptyPrivateKey, testMessage, signature));
    
    // Clave privada toda ceros
    std::vector<uint8_t> allZerosPrivateKey(PRIVATE_KEY_SIZE, 0x00);
    EXPECT_FALSE(SignatureManager::signMessage(allZerosPrivateKey, testMessage, signature));
    
    // Tamaño incorrecto
    std::vector<uint8_t> wrongSizePrivateKey(16, 0x01);
    EXPECT_FALSE(SignatureManager::signMessage(wrongSizePrivateKey, testMessage, signature));
    
    SignatureManager::secureClean(allZerosPrivateKey);
    SignatureManager::secureClean(wrongSizePrivateKey);
    SignatureManager::secureClean(signature);
}

TEST_F(SignatureManagerTest, SignWithInvalidEncodedPrivateKey) {
    // Base64 vacío
    EXPECT_TRUE(SignatureManager::signMessageEncoded("", testMessage).empty());
    
    // Base64 inválido
    EXPECT_TRUE(SignatureManager::signMessageEncoded("!!!invalid_base64!!!", testMessage).empty());
    
    // Base64 que no representa una clave privada válida
    std::string invalidKey = CryptoBase::base64Encode(std::vector<uint8_t>(16, 0x01));
    EXPECT_TRUE(SignatureManager::signMessageEncoded(invalidKey, testMessage).empty());
}

TEST_F(SignatureManagerTest, SignEmptyMessage) {
    std::vector<uint8_t> signature(SIGNATURE_SIZE);
    std::vector<uint8_t> emptyMessage;
    
    EXPECT_FALSE(SignatureManager::signMessage(testPrivateKey, emptyMessage, signature));
    EXPECT_TRUE(SignatureManager::signMessageEncoded(encodedPrivateKey, emptyMessage).empty());
    
    SignatureManager::secureClean(signature);
}

TEST_F(SignatureManagerTest, VerifyWithInvalidPublicKey) {
    // Clave pública vacía
    std::vector<uint8_t> emptyPublicKey;
    EXPECT_FALSE(SignatureManager::verifySignature(emptyPublicKey, testMessage, testSignature));
    
    // Clave pública toda ceros
    std::vector<uint8_t> allZerosPublicKey(PUBLIC_KEY_SIZE, 0x00);
    EXPECT_FALSE(SignatureManager::verifySignature(allZerosPublicKey, testMessage, testSignature));
    
    // Tamaño incorrecto
    std::vector<uint8_t> wrongSizePublicKey(16, 0x01);
    EXPECT_FALSE(SignatureManager::verifySignature(wrongSizePublicKey, testMessage, testSignature));
    
    SignatureManager::secureClean(allZerosPublicKey);
    SignatureManager::secureClean(wrongSizePublicKey);
}

TEST_F(SignatureManagerTest, VerifyWithInvalidSignature) {
    // Firma vacía
    std::vector<uint8_t> emptySignature;
    EXPECT_FALSE(SignatureManager::verifySignature(testPublicKey, testMessage, emptySignature));
    
    // Firma toda ceros
    std::vector<uint8_t> allZerosSignature(SIGNATURE_SIZE, 0x00);
    EXPECT_FALSE(SignatureManager::verifySignature(testPublicKey, testMessage, allZerosSignature));
    
    // Tamaño incorrecto
    std::vector<uint8_t> wrongSizeSignature(16, 0x01);
    EXPECT_FALSE(SignatureManager::verifySignature(testPublicKey, testMessage, wrongSizeSignature));
    
    SignatureManager::secureClean(allZerosSignature);
    SignatureManager::secureClean(wrongSizeSignature);
}

TEST_F(SignatureManagerTest, VerifyWithWrongPublicKey) {
    // Generar otro par de claves
    std::vector<uint8_t> privateKey2(PRIVATE_KEY_SIZE);
    std::vector<uint8_t> publicKey2(PUBLIC_KEY_SIZE);
    ASSERT_TRUE(KeyManager::generateKeyPair(privateKey2, publicKey2));
    
    // La firma creada con una clave no debería verificar con otra clave
    EXPECT_FALSE(SignatureManager::verifySignature(publicKey2, testMessage, testSignature));
    
    SignatureManager::secureClean(privateKey2);
    SignatureManager::secureClean(publicKey2);
}

TEST_F(SignatureManagerTest, VerifyWithWrongMessage) {
    std::vector<uint8_t> differentMessage = {0x44, 0x69, 0x66, 0x66, 0x65, 0x72, 0x65, 0x6E, 0x74}; // "Different"
    
    // La firma para un mensaje no debería verificar para otro mensaje
    EXPECT_FALSE(SignatureManager::verifySignature(testPublicKey, differentMessage, testSignature));
    
    CryptoBase::secureClean(differentMessage);
}

TEST_F(SignatureManagerTest, VerifyWithTamperedSignature) {
    std::vector<uint8_t> tamperedSignature = testSignature;
    
    // Modificar un byte de la firma
    if (!tamperedSignature.empty()) {
        tamperedSignature[0] ^= 0x01; // Flip un bit
    }
    
    EXPECT_FALSE(SignatureManager::verifySignature(testPublicKey, testMessage, tamperedSignature));
    
    SignatureManager::secureClean(tamperedSignature);
}

// ============================================================================
// SECCIÓN 4: TESTS DE VALIDACIÓN DE FIRMAS
// ============================================================================

TEST_F(SignatureManagerTest, IsValidSignatureBasic) {
    EXPECT_TRUE(SignatureManager::isValidSignature(testSignature));
}

TEST_F(SignatureManagerTest, IsValidSignatureEdgeCases) {
    // Firma vacía
    std::vector<uint8_t> emptySignature;
    EXPECT_FALSE(SignatureManager::isValidSignature(emptySignature));
    
    // Firma toda ceros
    std::vector<uint8_t> allZerosSignature(SIGNATURE_SIZE, 0x00);
    EXPECT_FALSE(SignatureManager::isValidSignature(allZerosSignature));
    
    // Firma con todos los bytes iguales
    std::vector<uint8_t> allSameSignature(SIGNATURE_SIZE, 0xAB);
    EXPECT_FALSE(SignatureManager::isValidSignature(allSameSignature));
    
    // Tamaño incorrecto
    std::vector<uint8_t> wrongSizeSignature(SIGNATURE_SIZE - 1, 0x01);
    EXPECT_FALSE(SignatureManager::isValidSignature(wrongSizeSignature));
    
    std::vector<uint8_t> wrongSizeSignature2(SIGNATURE_SIZE + 1, 0x01);
    EXPECT_FALSE(SignatureManager::isValidSignature(wrongSizeSignature2));
    
    SignatureManager::secureClean(allZerosSignature);
    SignatureManager::secureClean(allSameSignature);
    SignatureManager::secureClean(wrongSizeSignature);
    SignatureManager::secureClean(wrongSizeSignature2);
}

TEST_F(SignatureManagerTest, IsValidSignatureEncodedBasic) {
    EXPECT_TRUE(SignatureManager::isValidSignatureEncoded(encodedSignature));
}

TEST_F(SignatureManagerTest, IsValidSignatureEncodedEdgeCases) {
    // Base64 vacío
    EXPECT_FALSE(SignatureManager::isValidSignatureEncoded(""));
    
    // Base64 inválido
    EXPECT_FALSE(SignatureManager::isValidSignatureEncoded("!!!invalid_base64!!!"));
    
    // Base64 que no representa una firma válida
    std::string invalidSig = CryptoBase::base64Encode(std::vector<uint8_t>(16, 0x01));
    EXPECT_FALSE(SignatureManager::isValidSignatureEncoded(invalidSig));
}

// ============================================================================
// SECCIÓN 5: TESTS DE SEGURIDAD Y MEMORIA
// ============================================================================

TEST_F(SignatureManagerTest, SecureCleanFunctionality) {
    std::vector<uint8_t> sensitiveData = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<uint8_t> originalData = sensitiveData; // Copia
    
    ASSERT_FALSE(sensitiveData.empty());
    SignatureManager::secureClean(sensitiveData);
    EXPECT_FALSE(sensitiveData.empty());
    EXPECT_TRUE(isVectorCleaned(sensitiveData));
    EXPECT_EQ(sensitiveData.size(), originalData.size());
}

TEST_F(SignatureManagerTest, MemoryIsCleanedAfterEncodedSigning) {
    // Verificar que signMessageEncoded limpia la memoria interna
    std::string signature1 = SignatureManager::signMessageEncoded(encodedPrivateKey, testMessage);
    ASSERT_FALSE(signature1.empty());
    
    std::string signature2 = SignatureManager::signMessageEncoded(encodedPrivateKey, testMessage);
    ASSERT_FALSE(signature2.empty());
    
    // Las firmas deberían ser idénticas (misma clave y mensaje)
    EXPECT_EQ(signature1, signature2);
}

TEST_F(SignatureManagerTest, NoMemoryLeaksInErrorCases) {
    const int errorIterations = 10;
    
    for (int i = 0; i < errorIterations; ++i) {
        // Intentar operaciones que fallarán
        std::vector<uint8_t> signature(SIGNATURE_SIZE);
        
        // Firma con clave inválida
        std::vector<uint8_t> invalidKey(16, 0x01);
        bool signSuccess = SignatureManager::signMessage(invalidKey, testMessage, signature);
        EXPECT_FALSE(signSuccess);
        
        // Verificación con datos inválidos
        bool verifySuccess = SignatureManager::verifySignature(invalidKey, testMessage, signature);
        EXPECT_FALSE(verifySuccess);
        
        SignatureManager::secureClean(invalidKey);
        SignatureManager::secureClean(signature);
    }
}

// ============================================================================
// SECCIÓN 6: TESTS DE RENDIMIENTO
// ============================================================================

TEST_F(SignatureManagerTest, PerformanceSigning) {
    const int iterations = 50;
    auto start = std::chrono::high_resolution_clock::now();
    
    int successCount = 0;
    for (int i = 0; i < iterations; ++i) {
        std::vector<uint8_t> message = generateRandomMessage(256 + i * 10); // Mensajes de tamaño variable
        std::vector<uint8_t> signature(SIGNATURE_SIZE);
        
        if (SignatureManager::signMessage(testPrivateKey, message, signature)) {
            if (SignatureManager::isValidSignature(signature)) {
                ++successCount;
            }
            SignatureManager::secureClean(signature);
        }
        CryptoBase::secureClean(message);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    testMetrics["signing_throughput_ops_per_sec"] = 
        (iterations * 1000.0) / duration.count();
    testMetrics["signing_success_rate"] = 
        static_cast<double>(successCount) / iterations * 100.0;
    testMetrics["signing_total_operations"] = iterations;
    
    std::cout << "[PERFORMANCE] Signing: " << iterations 
              << " operations in " << duration.count() << "ms" << std::endl;
    std::cout << "[PERFORMANCE] Success rate: " 
              << testMetrics["signing_success_rate"] << "%" << std::endl;
    std::cout << "[PERFORMANCE] Throughput: " 
              << testMetrics["signing_throughput_ops_per_sec"] << " ops/sec" << std::endl;
    
    EXPECT_GE(successCount, iterations * 0.95); // 95% de éxito mínimo
}

TEST_F(SignatureManagerTest, PerformanceVerification) {
    const int iterations = 100;
    auto start = std::chrono::high_resolution_clock::now();
    
    int successCount = 0;
    for (int i = 0; i < iterations; ++i) {
        if (SignatureManager::verifySignature(testPublicKey, testMessage, testSignature)) {
            ++successCount;
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    testMetrics["verification_throughput_ops_per_sec"] = 
        (iterations * 1000.0) / duration.count();
    testMetrics["verification_success_rate"] = 
        static_cast<double>(successCount) / iterations * 100.0;
    
    EXPECT_EQ(successCount, iterations); // 100% de éxito esperado
}

TEST_F(SignatureManagerTest, PerformanceEncodedOperations) {
    const int iterations = 30;
    auto start = std::chrono::high_resolution_clock::now();
    
    int successCount = 0;
    for (int i = 0; i < iterations; ++i) {
        std::vector<uint8_t> message = generateRandomMessage(128);
        std::string signature = SignatureManager::signMessageEncoded(encodedPrivateKey, message);
        
        if (!signature.empty() && SignatureManager::isValidSignatureEncoded(signature)) {
            if (SignatureManager::verifySignatureEncoded(encodedPublicKey, message, signature)) {
                ++successCount;
            }
        }
        CryptoBase::secureClean(message);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    testMetrics["encoded_operations_throughput_ops_per_sec"] = 
        (iterations * 1000.0) / duration.count();
    testMetrics["encoded_operations_success_rate"] = 
        static_cast<double>(successCount) / iterations * 100.0;
    
    EXPECT_GE(successCount, iterations * 0.95); // 95% de éxito mínimo
}

// ============================================================================
// SECCIÓN 7: TESTS DE INTEGRACIÓN
// ============================================================================

TEST_F(SignatureManagerTest, IntegrationWithKeyManager) {
    // Verificar que SignatureManager funciona correctamente con KeyManager
    auto start = std::chrono::high_resolution_clock::now();
    
    // 1. Generar claves usando KeyManager
    std::string privateKeyEncoded, publicKeyEncoded;
    ASSERT_TRUE(KeyManager::generateKeyPairSecure(privateKeyEncoded, publicKeyEncoded));
    
    // 2. Firmar mensaje usando SignatureManager
    std::vector<uint8_t> message = {0x54, 0x65, 0x73, 0x74, 0x20, 0x4D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65}; // "Test Message"
    std::string signature = SignatureManager::signMessageEncoded(privateKeyEncoded, message);
    ASSERT_FALSE(signature.empty());
    
    // 3. Verificar firma
    bool isValid = SignatureManager::verifySignatureEncoded(publicKeyEncoded, message, signature);
    EXPECT_TRUE(isValid);
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["integration_with_keymanager_ms"] = 
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    CryptoBase::secureClean(message);
}

TEST_F(SignatureManagerTest, IntegrationWithCryptoBase) {
    // Verificar interoperabilidad con CryptoBase
    std::vector<uint8_t> message = generateRandomMessage(512);
    
    // Firmar
    std::vector<uint8_t> signature(SIGNATURE_SIZE);
    ASSERT_TRUE(SignatureManager::signMessage(testPrivateKey, message, signature));
    
    // Codificar con CryptoBase
    std::string encodedSig = CryptoBase::base64Encode(signature);
    EXPECT_FALSE(encodedSig.empty());
    
    // Decodificar y verificar
    std::vector<uint8_t> decodedSig = CryptoBase::base64Decode(encodedSig);
    EXPECT_EQ(signature, decodedSig);
    
    // Verificar con la firma decodificada
    bool isValid = SignatureManager::verifySignature(testPublicKey, message, decodedSig);
    EXPECT_TRUE(isValid);
    
    SignatureManager::secureClean(signature);
    SignatureManager::secureClean(decodedSig);
    CryptoBase::secureClean(message);
}

TEST_F(SignatureManagerTest, CompleteSignatureWorkflow) {
    // Simular un flujo completo de firma/verificación
    auto start = std::chrono::high_resolution_clock::now();
    
    // 1. Generación de claves (simulada - ya tenemos testPrivateKey/testPublicKey)
    
    // 2. Creación del mensaje
    std::vector<uint8_t> importantMessage = {
        0x49, 0x6D, 0x70, 0x6F, 0x72, 0x74, 0x61, 0x6E, 0x74, 0x20, 0x44, 0x61, 0x74, 0x61 // "Important Data"
    };
    
    // 3. Firma del mensaje
    std::vector<uint8_t> signature(SIGNATURE_SIZE);
    ASSERT_TRUE(SignatureManager::signMessage(testPrivateKey, importantMessage, signature));
    ASSERT_TRUE(SignatureManager::isValidSignature(signature));
    
    // 4. Codificación para transmisión
    std::string encodedMessage = CryptoBase::base64Encode(importantMessage);
    std::string encodedSignature = CryptoBase::base64Encode(signature);
    std::string encodedPublicKey = CryptoBase::base64Encode(testPublicKey);
    
    // 5. Simular recepción y decodificación
    std::vector<uint8_t> receivedMessage = CryptoBase::base64Decode(encodedMessage);
    std::vector<uint8_t> receivedSignature = CryptoBase::base64Decode(encodedSignature);
    std::vector<uint8_t> receivedPublicKey = CryptoBase::base64Decode(encodedPublicKey);
    
    // 6. Verificación de la firma
    bool verificationResult = SignatureManager::verifySignature(
        receivedPublicKey, receivedMessage, receivedSignature);
    EXPECT_TRUE(verificationResult);
    
    // 7. Limpieza
    SignatureManager::secureClean(signature);
    CryptoBase::secureClean(importantMessage);
    CryptoBase::secureClean(receivedMessage);
    CryptoBase::secureClean(receivedSignature);
    CryptoBase::secureClean(receivedPublicKey);
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["complete_workflow_ms"] = 
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
}

// ============================================================================
// SECCIÓN 8: TESTS DE ESTRÉS Y CARGA
// ============================================================================

TEST_F(SignatureManagerTest, StressTestMultipleSignatures) {
    const int stressIterations = 100;
    auto start = std::chrono::high_resolution_clock::now();
    
    int successCount = 0;
    for (int i = 0; i < stressIterations; ++i) {
        std::vector<uint8_t> message = generateRandomMessage(100 + i * 5); // Mensajes de tamaño creciente
        std::vector<uint8_t> signature(SIGNATURE_SIZE);
        
        if (SignatureManager::signMessage(testPrivateKey, message, signature)) {
            if (SignatureManager::verifySignature(testPublicKey, message, signature)) {
                ++successCount;
            }
            SignatureManager::secureClean(signature);
        }
        CryptoBase::secureClean(message);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    testMetrics["stress_test_success_rate"] = 
        static_cast<double>(successCount) / stressIterations * 100.0;
    testMetrics["stress_test_duration_ms"] = duration.count();
    
    std::cout << "[STRESS_TEST] Processed " << successCount 
              << "/" << stressIterations << " signatures in " 
              << duration.count() << "ms" << std::endl;
    
    EXPECT_GE(successCount, stressIterations * 0.98); // 98% de éxito mínimo
}

TEST_F(SignatureManagerTest, LargeMessageSigning) {
    // Probar con mensajes grandes
    std::vector<uint8_t> largeMessage = generateRandomMessage(1024 * 1024); // 1MB
    std::vector<uint8_t> signature(SIGNATURE_SIZE);
    
    auto start = std::chrono::high_resolution_clock::now();
    
    bool success = SignatureManager::signMessage(testPrivateKey, largeMessage, signature);
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    EXPECT_TRUE(success);
    EXPECT_TRUE(SignatureManager::isValidSignature(signature));
    
    // Verificar que la firma es correcta
    bool isValid = SignatureManager::verifySignature(testPublicKey, largeMessage, signature);
    EXPECT_TRUE(isValid);
    
    testMetrics["large_message_signing_ms"] = duration.count();
    
    SignatureManager::secureClean(signature);
    CryptoBase::secureClean(largeMessage);
}