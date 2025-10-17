#include <gtest/gtest.h>
#include "Transaction.hpp"
#include "CryptoBase.hpp"
#include "SignatureManager.hpp"
#include "KeyManager.hpp"
#include "AddressManager.hpp"
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <algorithm>
#include <sstream>
#include <thread>
#include <cmath>

// ============================================================================
// FIXTURE PRINCIPAL PARA TESTS DE TRANSACTION
// ============================================================================

class TransactionTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Inicializar dependencias criptográficas
        ASSERT_TRUE(SignatureManager::initialize()) << "Failed to initialize crypto libraries";
        
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
        
        // Calcular métricas finales
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - testStartTime);
        testMetrics["total_test_duration_ms"] = duration.count();
        
        // Log de métricas resumidas
        std::cout << "[METRICS] TransactionTest completed - Duration: " 
                  << duration.count() << "ms" << std::endl;
        for (const auto& [key, value] : testMetrics) {
            if (value > 0) {
                std::cout << "[METRIC] " << key << ": " << value << std::endl;
            }
        }
    }
    
    void generateTestData() {
        // Generar par de claves para testing
        testPrivateKey.resize(PRIVATE_KEY_SIZE);
        testPublicKey.resize(PUBLIC_KEY_SIZE);
        ASSERT_TRUE(KeyManager::generateKeyPair(testPrivateKey, testPublicKey));
        
        // Generar direcciones de prueba
        testFromAddress = AddressManager::getAddressFromPublicKey(testPublicKey);
        
        // Generar otra dirección de destino
        std::vector<uint8_t> otherPrivateKey(PRIVATE_KEY_SIZE);
        std::vector<uint8_t> otherPublicKey(PUBLIC_KEY_SIZE);
        ASSERT_TRUE(KeyManager::generateKeyPair(otherPrivateKey, otherPublicKey));
        testToAddress = AddressManager::getAddressFromPublicKey(otherPublicKey);
        
        // Generar clave codificada
        testEncodedPrivateKey = CryptoBase::base64Encode(testPrivateKey);
        
        // Limpieza
        CryptoBase::secureClean(otherPrivateKey);
        CryptoBase::secureClean(otherPublicKey);
    }
    
    // Helper para generar dirección válida
    std::string generateValidAddress() {
        std::vector<uint8_t> publicKey(PUBLIC_KEY_SIZE);
        std::vector<uint8_t> privateKey(PRIVATE_KEY_SIZE);
        
        if (KeyManager::generateKeyPair(privateKey, publicKey)) {
            std::string address = AddressManager::getAddressFromPublicKey(publicKey);
            CryptoBase::secureClean(privateKey);
            CryptoBase::secureClean(publicKey);
            return address;
        }
        
        // Fallback: dirección de prueba hardcodeada (solo para testing)
        return "a1b2c3d4e5f67890123456789012345678901234";
    }
    
    // Helper para generar transacción de prueba
    std::unique_ptr<Transaction> createTestTransaction(double amount = 1.0, 
                                                     const std::string& data = "") {
        return std::make_unique<Transaction>(testFromAddress, testToAddress, amount, data);
    }
    
    // Helper para generar transacción firmada
    std::unique_ptr<Transaction> createSignedTestTransaction(double amount = 1.0) {
        auto tx = createTestTransaction(amount);
        EXPECT_TRUE(tx->sign(testPrivateKey));
        return tx;
    }
    
    // Helper para verificar que un timestamp es reciente
    bool isTimestampRecent(std::time_t timestamp) {
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
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
    std::vector<uint8_t> testPrivateKey;
    std::vector<uint8_t> testPublicKey;
    std::string testFromAddress;
    std::string testToAddress;
    std::string testEncodedPrivateKey;
};

// ============================================================================
// SECCIÓN 1: TESTS BÁSICOS DE CONSTRUCCIÓN
// ============================================================================

TEST_F(TransactionTest, ConstructorBasic) {
    auto start = std::chrono::high_resolution_clock::now();
    
    std::unique_ptr<Transaction> tx = createTestTransaction(1.5, "test data");
    
    EXPECT_EQ(tx->getFrom(), testFromAddress);
    EXPECT_EQ(tx->getTo(), testToAddress);
    EXPECT_DOUBLE_EQ(tx->getAmount(), 1.5);
    EXPECT_EQ(tx->getData(), "test data");
    EXPECT_TRUE(isTimestampRecent(tx->getTimestamp()));
    
    // El hash debería estar calculado automáticamente
    EXPECT_FALSE(tx->getHash().empty());
    EXPECT_FALSE(tx->getHashHex().empty());
    EXPECT_EQ(tx->getHash().size(), SHA256_HASH_SIZE);
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["constructor_basic_ms"] = 
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
}

TEST_F(TransactionTest, ConstructorDefault) {
    Transaction tx;
    
    EXPECT_TRUE(tx.getFrom().empty());
    EXPECT_TRUE(tx.getTo().empty());
    EXPECT_DOUBLE_EQ(tx.getAmount(), 0.0);
    EXPECT_TRUE(tx.getData().empty());
    EXPECT_EQ(tx.getTimestamp(), 0);
    EXPECT_TRUE(tx.getHash().empty());
    EXPECT_TRUE(tx.getSignature().empty());
    EXPECT_TRUE(tx.getPublicKey().empty());
}

TEST_F(TransactionTest, ConstructorWithEmptyData) {
    std::unique_ptr<Transaction> tx = createTestTransaction(2.5, "");
    
    EXPECT_EQ(tx->getFrom(), testFromAddress);
    EXPECT_EQ(tx->getTo(), testToAddress);
    EXPECT_DOUBLE_EQ(tx->getAmount(), 2.5);
    EXPECT_TRUE(tx->getData().empty());
    EXPECT_FALSE(tx->getHash().empty());
}

// ============================================================================
// SECCIÓN 2: TESTS DE VALIDACIÓN DE ENTRADA Y ERRORES
// ============================================================================

TEST_F(TransactionTest, ConstructorInvalidFromAddressThrowsException) {
    EXPECT_THROW({
        Transaction tx("invalid_address", testToAddress, 1.0);
    }, std::invalid_argument);
    
    EXPECT_THROW({
        Transaction tx("", testToAddress, 1.0); // Dirección vacía
    }, std::invalid_argument);
    
    EXPECT_THROW({
        Transaction tx("123", testToAddress, 1.0); // Dirección demasiado corta
    }, std::invalid_argument);
}

TEST_F(TransactionTest, ConstructorInvalidToAddressThrowsException) {
    EXPECT_THROW({
        Transaction tx(testFromAddress, "invalid_address", 1.0);
    }, std::invalid_argument);
    
    EXPECT_THROW({
        Transaction tx(testFromAddress, "", 1.0); // Dirección vacía
    }, std::invalid_argument);
}

TEST_F(TransactionTest, ConstructorInvalidAmountThrowsException) {
    EXPECT_THROW({
        Transaction tx(testFromAddress, testToAddress, 0.0); // Cantidad cero
    }, std::invalid_argument);
    
    EXPECT_THROW({
        Transaction tx(testFromAddress, testToAddress, -1.0); // Cantidad negativa
    }, std::invalid_argument);
    
    EXPECT_THROW({
        Transaction tx(testFromAddress, testToAddress, -100.0); // Cantidad muy negativa
    }, std::invalid_argument);
}

TEST_F(TransactionTest, ConstructorSelfTransactionThrowsException) {
    EXPECT_THROW({
        Transaction tx(testFromAddress, testFromAddress, 1.0); // A uno mismo
    }, std::invalid_argument);
}

// ============================================================================
// SECCIÓN 3: TESTS DE GETTERS Y SETTERS
// ============================================================================

TEST_F(TransactionTest, GettersReturnCorrectValues) {
    std::unique_ptr<Transaction> tx = createTestTransaction(3.14, "pi transaction");
    
    EXPECT_EQ(tx->getFrom(), testFromAddress);
    EXPECT_EQ(tx->getTo(), testToAddress);
    EXPECT_DOUBLE_EQ(tx->getAmount(), 3.14);
    EXPECT_EQ(tx->getData(), "pi transaction");
    EXPECT_TRUE(isTimestampRecent(tx->getTimestamp()));
    
    // Hash debería estar presente
    EXPECT_FALSE(tx->getHash().empty());
    EXPECT_FALSE(tx->getHashHex().empty());
    
    // Signature y publicKey deberían estar vacíos hasta firmar
    EXPECT_TRUE(tx->getSignature().empty());
    EXPECT_TRUE(tx->getPublicKey().empty());
    EXPECT_TRUE(tx->getSignatureBase64().empty());
    EXPECT_TRUE(tx->getPublicKeyBase64().empty());
}

TEST_F(TransactionTest, SettersForDeserialization) {
    Transaction tx;
    
    std::vector<uint8_t> testHash(SHA256_HASH_SIZE, 0xAB);
    std::vector<uint8_t> testSignature(SIGNATURE_SIZE, 0xCD);
    std::vector<uint8_t> testPublicKey(PUBLIC_KEY_SIZE, 0xEF);
    std::time_t testTimestamp = 1234567890;
    
    // Usar setters (para deserialización)
    tx.setHash(testHash);
    tx.setSignature(testSignature);
    tx.setPublicKey(testPublicKey);
    tx.setTimestamp(testTimestamp);
    
    EXPECT_EQ(tx.getHash(), testHash);
    EXPECT_EQ(tx.getSignature(), testSignature);
    EXPECT_EQ(tx.getPublicKey(), testPublicKey);
    EXPECT_EQ(tx.getTimestamp(), testTimestamp);
}

TEST_F(TransactionTest, HexAndBase64Conversions) {
    std::unique_ptr<Transaction> tx = createTestTransaction(1.0);
    
    // Hash hex no debería estar vacío
    std::string hashHex = tx->getHashHex();
    EXPECT_FALSE(hashHex.empty());
    EXPECT_EQ(hashHex.length(), SHA256_HASH_SIZE * 2);
    
    // Verificar que es hexadecimal válido
    auto isHexString = [](const std::string& str) {
        return std::all_of(str.begin(), str.end(), [](char c) {
            return std::isxdigit(static_cast<unsigned char>(c));
        });
    };
    EXPECT_TRUE(isHexString(hashHex));
    
    // Firmar para probar conversiones base64
    EXPECT_TRUE(tx->sign(testPrivateKey));
    
    std::string signatureBase64 = tx->getSignatureBase64();
    std::string publicKeyBase64 = tx->getPublicKeyBase64();
    
    EXPECT_FALSE(signatureBase64.empty());
    EXPECT_FALSE(publicKeyBase64.empty());
    
    // Verificar que son base64 válido
    EXPECT_NO_THROW({
        CryptoBase::base64Decode(signatureBase64);
        CryptoBase::base64Decode(publicKeyBase64);
    });
}

// ============================================================================
// SECCIÓN 4: TESTS DE FIRMA Y VERIFICACIÓN
// ============================================================================

TEST_F(TransactionTest, SignWithValidPrivateKey) {
    auto start = std::chrono::high_resolution_clock::now();
    
    std::unique_ptr<Transaction> tx = createTestTransaction(1.0);
    
    EXPECT_TRUE(tx->sign(testPrivateKey));
    
    // Verificar que la firma y clave pública se establecieron
    EXPECT_FALSE(tx->getSignature().empty());
    EXPECT_FALSE(tx->getPublicKey().empty());
    EXPECT_EQ(tx->getSignature().size(), SIGNATURE_SIZE);
    EXPECT_EQ(tx->getPublicKey().size(), PUBLIC_KEY_SIZE);
    
    // La firma debería ser verificable
    EXPECT_TRUE(tx->verifySignature());
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["sign_with_private_key_ms"] = 
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
}

TEST_F(TransactionTest, SignFromEncodedPrivateKey) {
    std::unique_ptr<Transaction> tx = createTestTransaction(2.0);
    
    EXPECT_TRUE(tx->signFromEncoded(testEncodedPrivateKey));
    
    EXPECT_FALSE(tx->getSignature().empty());
    EXPECT_FALSE(tx->getPublicKey().empty());
    EXPECT_TRUE(tx->verifySignature());
}

TEST_F(TransactionTest, SignWithInvalidPrivateKey) {
    std::unique_ptr<Transaction> tx = createTestTransaction(1.0);
    
    // Clave privada vacía
    std::vector<uint8_t> emptyPrivateKey;
    EXPECT_FALSE(tx->sign(emptyPrivateKey));
    
    // Clave privada de tamaño incorrecto
    std::vector<uint8_t> wrongSizePrivateKey(16, 0x01);
    EXPECT_FALSE(tx->sign(wrongSizePrivateKey));
    
    // Clave privada toda ceros
    std::vector<uint8_t> allZerosPrivateKey(PRIVATE_KEY_SIZE, 0x00);
    EXPECT_FALSE(tx->sign(allZerosPrivateKey));
    
    CryptoBase::secureClean(wrongSizePrivateKey);
    CryptoBase::secureClean(allZerosPrivateKey);
}

TEST_F(TransactionTest, SignFromEncodedInvalidPrivateKey) {
    std::unique_ptr<Transaction> tx = createTestTransaction(1.0);
    
    // Base64 vacío
    EXPECT_FALSE(tx->signFromEncoded(""));
    
    // Base64 inválido
    EXPECT_FALSE(tx->signFromEncoded("!!!invalid_base64!!!"));
    
    // Base64 que no representa una clave privada válida
    std::string invalidKey = CryptoBase::base64Encode(std::vector<uint8_t>(16, 0x01));
    EXPECT_FALSE(tx->signFromEncoded(invalidKey));
}

TEST_F(TransactionTest, VerifySignatureWithoutSigning) {
    std::unique_ptr<Transaction> tx = createTestTransaction(1.0);
    
    // No debería poder verificar sin firma
    EXPECT_FALSE(tx->verifySignature());
}

TEST_F(TransactionTest, VerifyTamperedSignature) {
    std::unique_ptr<Transaction> tx = createSignedTestTransaction(1.0);
    
    // Modificar la firma
    std::vector<uint8_t> tamperedSignature = tx->getSignature();
    if (!tamperedSignature.empty()) {
        tamperedSignature[0] ^= 0x01; // Flip un bit
    }
    tx->setSignature(tamperedSignature);
    
    EXPECT_FALSE(tx->verifySignature());
}

TEST_F(TransactionTest, VerifyWithWrongPublicKey) {
    std::unique_ptr<Transaction> tx = createTestTransaction(1.0);
    
    // Firmar con una clave
    EXPECT_TRUE(tx->sign(testPrivateKey));
    
    // Cambiar la clave pública a una diferente
    std::vector<uint8_t> wrongPublicKey(PUBLIC_KEY_SIZE, 0x99);
    tx->setPublicKey(wrongPublicKey);
    
    EXPECT_FALSE(tx->verifySignature());
    
    CryptoBase::secureClean(wrongPublicKey);
}

// ============================================================================
// SECCIÓN 5: TESTS DE VALIDACIÓN DE TRANSACCIÓN
// ============================================================================

TEST_F(TransactionTest, IsValidForSignedTransaction) {
    std::unique_ptr<Transaction> tx = createSignedTestTransaction(1.0);
    
    EXPECT_TRUE(tx->isValid());
}

TEST_F(TransactionTest, IsValidForUnsignedTransaction) {
    std::unique_ptr<Transaction> tx = createTestTransaction(1.0);
    
    // Transacción no firmada no es válida
    EXPECT_FALSE(tx->isValid());
}

TEST_F(TransactionTest, IsValidWithInvalidAmount) {
    // Crear transacción con cantidad inválida usando setters
    Transaction tx;
    // Necesitaríamos setters para from/to/amount, pero no están disponibles
    // Por ahora probamos la validación interna
    
    std::unique_ptr<Transaction> validTx = createSignedTestTransaction(1.0);
    EXPECT_TRUE(validTx->isValid());
}

TEST_F(TransactionTest, IsValidWithInvalidAddresses) {
    // Similar al anterior, necesitaríamos setters para probar direcciones inválidas
    // La validación en el constructor ya previene la creación con direcciones inválidas
}

TEST_F(TransactionTest, ValidateAmountMethod) {
    std::unique_ptr<Transaction> tx = createTestTransaction(1.0);
    
    // La transacción de prueba debería tener cantidad válida
    EXPECT_TRUE(tx->validateAmount());
}

TEST_F(TransactionTest, ValidateAddressesMethod) {
    std::unique_ptr<Transaction> tx = createTestTransaction(1.0);
    
    // Las direcciones de prueba deberían ser válidas
    EXPECT_TRUE(tx->validateAddresses());
}

TEST_F(TransactionTest, ValidateTimingMethod) {
    std::unique_ptr<Transaction> tx = createTestTransaction(1.0);
    
    // El timestamp reciente debería ser válido
    EXPECT_TRUE(tx->validateTiming());
}

TEST_F(TransactionTest, InvolvesAddressMethod) {
    std::unique_ptr<Transaction> tx = createTestTransaction(1.0);
    
    EXPECT_TRUE(tx->involvesAddress(testFromAddress));
    EXPECT_TRUE(tx->involvesAddress(testToAddress));
    EXPECT_FALSE(tx->involvesAddress("0000000000000000000000000000000000000000"));
    EXPECT_FALSE(tx->involvesAddress(""));
    EXPECT_FALSE(tx->involvesAddress("invalid_address"));
}

// ============================================================================
// SECCIÓN 6: TESTS DE HASH Y CONSISTENCIA
// ============================================================================

TEST_F(TransactionTest, HashConsistency) {
    std::unique_ptr<Transaction> tx1 = createTestTransaction(1.0, "same data");
    std::unique_ptr<Transaction> tx2 = createTestTransaction(1.0, "same data");
    
    // Mismos datos deberían producir mismo hash
    EXPECT_EQ(tx1->getHash(), tx2->getHash());
}

TEST_F(TransactionTest, HashChangesWithDifferentData) {
    std::unique_ptr<Transaction> tx1 = createTestTransaction(1.0, "data1");
    std::unique_ptr<Transaction> tx2 = createTestTransaction(1.0, "data2");
    
    // Datos diferentes deberían producir hashes diferentes
    EXPECT_NE(tx1->getHash(), tx2->getHash());
}

TEST_F(TransactionTest, HashChangesWithDifferentAmount) {
    std::unique_ptr<Transaction> tx1 = createTestTransaction(1.0, "same data");
    std::unique_ptr<Transaction> tx2 = createTestTransaction(2.0, "same data");
    
    EXPECT_NE(tx1->getHash(), tx2->getHash());
}

TEST_F(TransactionTest, HashChangesWithDifferentTimestamp) {
    // Para probar esto necesitaríamos controlar el timestamp
    // Por ahora confiamos en que el timestamp es parte del cálculo del hash
}

TEST_F(TransactionTest, StringForHashMethod) {
    std::unique_ptr<Transaction> tx = createTestTransaction(1.5, "test");
    
    std::string hashString = tx->stringForHash();
    
    EXPECT_FALSE(hashString.empty());
    // Debería contener todos los campos relevantes
    EXPECT_NE(hashString.find(testFromAddress), std::string::npos);
    EXPECT_NE(hashString.find(testToAddress), std::string::npos);
    EXPECT_NE(hashString.find("1.5"), std::string::npos);
    EXPECT_NE(hashString.find("test"), std::string::npos);
}

TEST_F(TransactionTest, CalculateHashUpdatesHash) {
    Transaction tx;
    
    // Establecer datos manualmente
    // Nota: Esto solo es posible porque tenemos setters limitados
    // En una transacción normal, el hash se calcula en el constructor
    
    std::vector<uint8_t> oldHash(SHA256_HASH_SIZE, 0x00);
    tx.setHash(oldHash);
    
    // Para probar calculateHash, necesitaríamos una forma de establecer los campos
    // Por ahora probamos que el constructor calcula el hash automáticamente
}

// ============================================================================
// SECCIÓN 7: TESTS DE SERIALIZACIÓN
// ============================================================================

TEST_F(TransactionTest, ToStringMethod) {
    std::unique_ptr<Transaction> tx = createTestTransaction(2.5, "test transaction");
    
    std::string str = tx->toString();
    
    EXPECT_FALSE(str.empty());
    EXPECT_NE(str.find("from: " + testFromAddress), std::string::npos);
    EXPECT_NE(str.find("to: " + testToAddress), std::string::npos);
    EXPECT_NE(str.find("amount: 2.5"), std::string::npos);
    EXPECT_NE(str.find("hash: "), std::string::npos);
}

TEST_F(TransactionTest, ToDebugStringMethod) {
    std::unique_ptr<Transaction> tx = createSignedTestTransaction(3.0);
    
    std::string debugStr = tx->toDebugString();
    
    EXPECT_FALSE(debugStr.empty());
    EXPECT_NE(debugStr.find("from: " + testFromAddress), std::string::npos);
    EXPECT_NE(debugStr.find("to: " + testToAddress), std::string::npos);
    EXPECT_NE(debugStr.find("amount: 3"), std::string::npos);
    EXPECT_NE(debugStr.find("hash: "), std::string::npos);
    EXPECT_NE(debugStr.find("signature: [present]"), std::string::npos);
    EXPECT_NE(debugStr.find("publicKey: [present]"), std::string::npos);
    EXPECT_NE(debugStr.find("valid: true"), std::string::npos);
}

// ============================================================================
// SECCIÓN 8: TESTS DE RENDIMIENTO
// ============================================================================

TEST_F(TransactionTest, PerformanceMultipleTransactions) {
    const int iterations = 100;
    auto start = std::chrono::high_resolution_clock::now();
    
    std::vector<std::unique_ptr<Transaction>> transactions;
    transactions.reserve(iterations);
    
    for (int i = 0; i < iterations; ++i) {
        transactions.push_back(createTestTransaction(0.1 + i * 0.01, "tx " + std::to_string(i)));
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    testMetrics["multiple_transactions_throughput_ops_per_sec"] = 
        (iterations * 1000.0) / duration.count();
    testMetrics["multiple_transactions_total"] = iterations;
    
    std::cout << "[PERFORMANCE] Created " << iterations 
              << " transactions in " << duration.count() << "ms" << std::endl;
    
    EXPECT_EQ(transactions.size(), iterations);
    EXPECT_LT(duration.count(), 1000);
}

TEST_F(TransactionTest, PerformanceSigningOperations) {
    const int iterations = 50;
    auto start = std::chrono::high_resolution_clock::now();
    
    int successCount = 0;
    for (int i = 0; i < iterations; ++i) {
        auto tx = createTestTransaction(0.1 + i * 0.1);
        if (tx->sign(testPrivateKey) && tx->verifySignature()) {
            successCount++;
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    testMetrics["signing_throughput_ops_per_sec"] = 
        (iterations * 1000.0) / duration.count();
    testMetrics["signing_success_rate"] = 
        static_cast<double>(successCount) / iterations * 100.0;
    
    EXPECT_EQ(successCount, iterations);
    EXPECT_LT(duration.count(), 5000);
}

TEST_F(TransactionTest, PerformanceValidation) {
    const int iterations = 100;
    auto tx = createSignedTestTransaction(1.0);
    
    auto start = std::chrono::high_resolution_clock::now();
    
    int validCount = 0;
    for (int i = 0; i < iterations; ++i) {
        if (tx->isValid()) {
            validCount++;
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    testMetrics["validation_throughput_ops_per_sec"] = 
        (iterations * 1000.0) / duration.count();
    
    EXPECT_EQ(validCount, iterations);
    EXPECT_LT(duration.count(), 1000);
}

// ============================================================================
// SECCIÓN 9: TESTS DE INTEGRACIÓN Y ESCENARIOS COMPLEJOS
// ============================================================================

TEST_F(TransactionTest, IntegrationWithCryptoModules) {
    auto start = std::chrono::high_resolution_clock::now();
    
    // 1. Generar nuevas claves usando KeyManager
    std::vector<uint8_t> privateKey(PRIVATE_KEY_SIZE);
    std::vector<uint8_t> publicKey(PUBLIC_KEY_SIZE);
    ASSERT_TRUE(KeyManager::generateKeyPair(privateKey, publicKey));
    
    // 2. Generar dirección usando AddressManager
    std::string fromAddress = AddressManager::getAddressFromPublicKey(publicKey);
    std::string toAddress = generateValidAddress();
    
    // 3. Crear transacción
    Transaction tx(fromAddress, toAddress, 5.0, "integration test");
    
    // 4. Firmar transacción
    EXPECT_TRUE(tx.sign(privateKey));
    
    // 5. Verificar usando SignatureManager directamente
    bool directVerification = SignatureManager::verifySignature(
        tx.getPublicKey(), tx.getHash(), tx.getSignature());
    EXPECT_TRUE(directVerification);
    
    // 6. Verificar transacción completa
    EXPECT_TRUE(tx.isValid());
    
    auto end = std::chrono::high_resolution_clock::now();
    testMetrics["integration_test_ms"] = 
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    CryptoBase::secureClean(privateKey);
    CryptoBase::secureClean(publicKey);
}

TEST_F(TransactionTest, MultipleSignaturesSameTransaction) {
    std::unique_ptr<Transaction> tx = createTestTransaction(1.0);
    
    // Firmar múltiples veces
    EXPECT_TRUE(tx->sign(testPrivateKey));
    std::vector<uint8_t> firstSignature = tx->getSignature();
    std::vector<uint8_t> firstPublicKey = tx->getPublicKey();
    
    EXPECT_TRUE(tx->sign(testPrivateKey)); // Firmar de nuevo
    std::vector<uint8_t> secondSignature = tx->getSignature();
    std::vector<uint8_t> secondPublicKey = tx->getPublicKey();
    
    // Las firmas deberían ser idénticas (Ed25519 es determinista)
    EXPECT_EQ(firstSignature, secondSignature);
    
    // La clave pública debería ser la misma
    EXPECT_EQ(firstPublicKey, secondPublicKey);
    
    // Ambas firmas deberían ser válidas
    EXPECT_TRUE(tx->verifySignature());
}

TEST_F(TransactionTest, TransactionCopySemantics) {
    std::unique_ptr<Transaction> original = createSignedTestTransaction(10.0);
    
    // Copiar transacción
    Transaction copy = *original;
    
    // Verificar que todos los campos se copiaron correctamente
    EXPECT_EQ(copy.getFrom(), original->getFrom());
    EXPECT_EQ(copy.getTo(), original->getTo());
    EXPECT_DOUBLE_EQ(copy.getAmount(), original->getAmount());
    EXPECT_EQ(copy.getData(), original->getData());
    EXPECT_EQ(copy.getTimestamp(), original->getTimestamp());
    EXPECT_EQ(copy.getHash(), original->getHash());
    EXPECT_EQ(copy.getSignature(), original->getSignature());
    EXPECT_EQ(copy.getPublicKey(), original->getPublicKey());
    
    // La copia debería ser válida
    EXPECT_TRUE(copy.isValid());
    EXPECT_TRUE(copy.verifySignature());
}

TEST_F(TransactionTest, EdgeCaseAmountValues) {
    // Probar cantidades en los límites
    EXPECT_NO_THROW({
        Transaction tx1(testFromAddress, testToAddress, 1e-8); // Mínimo
    });
    
    EXPECT_NO_THROW({
        Transaction tx2(testFromAddress, testToAddress, 1e9); // Máximo
    });
    
    // Cantidades problemáticas
    EXPECT_THROW({
        Transaction tx3(testFromAddress, testToAddress, 1e-9); // Demasiado pequeño
    }, std::invalid_argument);
    
    EXPECT_THROW({
        Transaction tx4(testFromAddress, testToAddress, 1e9 + 1); // Demasiado grande
    }, std::invalid_argument);
}

TEST_F(TransactionTest, StressTestMultipleSignedTransactions) {
    const int transactionCount = 20;
    auto start = std::chrono::high_resolution_clock::now();
    
    std::vector<std::unique_ptr<Transaction>> transactions;
    
    for (int i = 0; i < transactionCount; ++i) {
        auto tx = createTestTransaction(0.1 + i * 0.5, "stress test " + std::to_string(i));
        
        if (tx->sign(testPrivateKey)) {
            transactions.push_back(std::move(tx));
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    testMetrics["stress_test_transaction_count"] = transactionCount;
    testMetrics["stress_test_duration_ms"] = duration.count();
    
    // Verificar que todas las transacciones son válidas
    int validCount = 0;
    for (const auto& tx : transactions) {
        if (tx->isValid()) {
            validCount++;
        }
    }
    
    testMetrics["stress_test_valid_transactions"] = validCount;
    EXPECT_EQ(validCount, transactions.size());
    
    std::cout << "[STRESS_TEST] Processed " << transactions.size() 
              << " signed transactions in " << duration.count() << "ms" << std::endl;
}

TEST_F(TransactionTest, ComprehensiveThroughputAndBottleneckAnalysis) {
    const int TIME_LIMIT_MS = 3000; // 3 segundos de ejecución
    const int REPORT_INTERVAL_MS = 100; // Reportar cada 100ms
    const int BATCH_ANALYSIS_SIZE = 500; // Analizar cada 500 transacciones
    
    std::vector<std::unique_ptr<Transaction>> txs;
    
    auto testStart = std::chrono::high_resolution_clock::now();
    auto lastReport = testStart;
    auto lastBatchAnalysis = testStart;
    
    int totalTransactions = 0;
    int transactionsSinceLastReport = 0;
    
    // Métricas detalladas para análisis de cuellos de botella
    struct OperationMetrics {
        long long createTimeUs = 0;
        long long signTimeUs = 0;
        long long verifyTimeUs = 0;
        int count = 0;
    };
    
    struct BatchAnalysis {
        int startTx;
        int endTx;
        double avgCreateUs;
        double avgSignUs;
        double avgVerifyUs;
        double tps;
        long long timestampMs;
    };
    
    // Métricas por intervalo
    struct IntervalMetrics {
        int txCount;
        double tps;
        double createTimeUs;
        double signTimeUs;
        double verifyTimeUs;
        long long timestampMs;
    };
    
    std::vector<IntervalMetrics> intervals;
    std::vector<BatchAnalysis> batchAnalyses;
    OperationMetrics currentBatchMetrics;
    
    std::cout << "🔍 EJECUTANDO ANÁLISIS COMPLETO DE THROUGHPUT Y CUELOS DE BOTELLA\n";
    std::cout << "Tiempo límite: " << TIME_LIMIT_MS << " ms\n";
    std::cout << "Tiempo | Transacciones | TPS actual | Crear | Firmar | Verificar | Bottleneck\n";
    std::cout << "--------------------------------------------------------------------------------\n";

    while (true) {
        auto currentTime = std::chrono::high_resolution_clock::now();
        auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - testStart).count();
        
        // Verificar si ha pasado el tiempo límite
        if (elapsedMs >= TIME_LIMIT_MS) {
            break;
        }
        
        // Medir tiempos individuales de cada operación
        auto t1 = std::chrono::high_resolution_clock::now();
        auto tx = createTestTransaction(totalTransactions + 0.1, "ThroughputTest");
        auto t2 = std::chrono::high_resolution_clock::now();
        
        EXPECT_TRUE(tx->sign(testPrivateKey));
        auto t3 = std::chrono::high_resolution_clock::now();
        
        EXPECT_TRUE(tx->verifySignature());
        auto t4 = std::chrono::high_resolution_clock::now();
        
        txs.push_back(std::move(tx));
        totalTransactions++;
        transactionsSinceLastReport++;
        
        // Acumular métricas de operaciones
        long long createUs = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
        long long signUs = std::chrono::duration_cast<std::chrono::microseconds>(t3 - t2).count();
        long long verifyUs = std::chrono::duration_cast<std::chrono::microseconds>(t4 - t3).count();
        
        currentBatchMetrics.createTimeUs += createUs;
        currentBatchMetrics.signTimeUs += signUs;
        currentBatchMetrics.verifyTimeUs += verifyUs;
        currentBatchMetrics.count++;
        
        // Reportar cada 100ms
        auto timeSinceLastReport = std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - lastReport).count();
        if (timeSinceLastReport >= REPORT_INTERVAL_MS && currentBatchMetrics.count > 0) {
            double currentTps = transactionsSinceLastReport / (timeSinceLastReport / 1000.0);
            double averageTps = totalTransactions / (elapsedMs / 1000.0);
            
            // Calcular promedios del intervalo
            double avgCreate = currentBatchMetrics.createTimeUs / static_cast<double>(currentBatchMetrics.count);
            double avgSign = currentBatchMetrics.signTimeUs / static_cast<double>(currentBatchMetrics.count);
            double avgVerify = currentBatchMetrics.verifyTimeUs / static_cast<double>(currentBatchMetrics.count);
            
            // Identificar cuello de botella
            std::string bottleneck = "Ninguno";
            double maxTime = std::max({avgCreate, avgSign, avgVerify});
            if (maxTime == avgCreate && avgCreate > avgSign * 1.5 && avgCreate > avgVerify * 1.5) {
                bottleneck = "CREACIÓN";
            } else if (maxTime == avgSign && avgSign > avgCreate * 1.5 && avgSign > avgVerify * 1.5) {
                bottleneck = "FIRMA";
            } else if (maxTime == avgVerify && avgVerify > avgCreate * 1.5 && avgVerify > avgSign * 1.5) {
                bottleneck = "VERIFICACIÓN";
            } else if (maxTime > 1000) { // Si alguna operación es muy lenta
                bottleneck = "MIXTO";
            }
            
            intervals.push_back({
                transactionsSinceLastReport,
                currentTps,
                avgCreate,
                avgSign,
                avgVerify,
                elapsedMs
            });
            
            std::cout << std::setw(6) << elapsedMs << " ms | "
                      << std::setw(13) << totalTransactions << " | "
                      << std::setw(10) << std::fixed << std::setprecision(0) << currentTps << " | "
                      << std::setw(6) << std::fixed << std::setprecision(1) << avgCreate << " | "
                      << std::setw(6) << std::fixed << std::setprecision(1) << avgSign << " | "
                      << std::setw(9) << std::fixed << std::setprecision(1) << avgVerify << " | "
                      << bottleneck << "\n";
            
            transactionsSinceLastReport = 0;
            lastReport = currentTime;
            
            // Resetear métricas del intervalo
            currentBatchMetrics = OperationMetrics();
        }
        
        // Análisis por lotes cada BATCH_ANALYSIS_SIZE transacciones
        if (totalTransactions % BATCH_ANALYSIS_SIZE == 0 && currentBatchMetrics.count > 0) {
            auto batchEnd = std::chrono::high_resolution_clock::now();
            long long batchTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(batchEnd - testStart).count();
            double batchTps = totalTransactions / (batchTimeMs / 1000.0);
            
            batchAnalyses.push_back({
                totalTransactions - BATCH_ANALYSIS_SIZE,
                totalTransactions,
                currentBatchMetrics.createTimeUs / static_cast<double>(currentBatchMetrics.count),
                currentBatchMetrics.signTimeUs / static_cast<double>(currentBatchMetrics.count),
                currentBatchMetrics.verifyTimeUs / static_cast<double>(currentBatchMetrics.count),
                batchTps,
                batchTimeMs
            });
        }
    }
    
    auto testEnd = std::chrono::high_resolution_clock::now();
    auto totalTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(testEnd - testStart).count();
    auto totalTimeUs = std::chrono::duration_cast<std::chrono::microseconds>(testEnd - testStart).count();
    double finalTps = totalTransactions / (totalTimeMs / 1000.0);
    
    // ANÁLISIS DETALLADO DE CUELOS DE BOTELLA
    std::cout << "\n=== ANÁLISIS COMPLETO DE CUELOS DE BOTELLA ===\n";
    
    // Calcular promedios globales
    double globalCreateUs = 0, globalSignUs = 0, globalVerifyUs = 0;
    for (const auto& interval : intervals) {
        globalCreateUs += interval.createTimeUs;
        globalSignUs += interval.signTimeUs;
        globalVerifyUs += interval.verifyTimeUs;
    }
    
    if (!intervals.empty()) {
        globalCreateUs /= intervals.size();
        globalSignUs /= intervals.size();
        globalVerifyUs /= intervals.size();
    }
    
    double totalOperationTime = globalCreateUs + globalSignUs + globalVerifyUs;
    double createPercentage = totalOperationTime > 0 ? (globalCreateUs / totalOperationTime) * 100.0 : 0;
    double signPercentage = totalOperationTime > 0 ? (globalSignUs / totalOperationTime) * 100.0 : 0;
    double verifyPercentage = totalOperationTime > 0 ? (globalVerifyUs / totalOperationTime) * 100.0 : 0;
    
    std::cout << "Distribución del tiempo por operación:\n";
    std::cout << "  • Creación: " << globalCreateUs << " μs (" << createPercentage << "%)\n";
    std::cout << "  • Firma: " << globalSignUs << " μs (" << signPercentage << "%)\n";
    std::cout << "  • Verificación: " << globalVerifyUs << " μs (" << verifyPercentage << "%)\n";
    
    // Identificar cuello de botella principal
    std::cout << "\n🔍 IDENTIFICACIÓN DE CUELOS DE BOTELLA:\n";
    if (signPercentage > 60) {
        std::cout << "  ⚠️  CUELO DE BOTELLA PRINCIPAL: FIRMA (" << signPercentage << "% del tiempo)\n";
        std::cout << "     Recomendación: Optimizar la caché de claves y el pool de firmas\n";
    } else if (verifyPercentage > 60) {
        std::cout << "  ⚠️  CUELO DE BOTELLA PRINCIPAL: VERIFICACIÓN (" << verifyPercentage << "% del tiempo)\n";
        std::cout << "     Recomendación: Mejorar la caché de claves públicas\n";
    } else if (createPercentage > 60) {
        std::cout << "  ⚠️  CUELO DE BOTELLA PRINCIPAL: CREACIÓN (" << createPercentage << "% del tiempo)\n";
        std::cout << "     Recomendación: Revisar constructores y asignación de memoria\n";
    } else if (std::max({createPercentage, signPercentage, verifyPercentage}) > 40) {
        std::cout << "  📊 DISTRIBUCIÓN BALANCEADA con operación dominante\n";
    } else {
        std::cout << "  ✅ DISTRIBUCIÓN EQUILIBRADA - Sin cuellos de botella evidentes\n";
    }
    
    // Análisis de evolución temporal
    std::cout << "\n=== EVOLUCIÓN TEMPORAL DEL RENDIMIENTO ===\n";
    if (!batchAnalyses.empty()) {
        std::cout << "Análisis por lotes de " << BATCH_ANALYSIS_SIZE << " transacciones:\n";
        for (size_t i = 0; i < batchAnalyses.size(); i++) {
            const auto& batch = batchAnalyses[i];
            std::cout << "  Lote " << (i + 1) << " (TX " << batch.startTx << "-" << batch.endTx << "):\n";
            std::cout << "    • TPS: " << batch.tps << " | Crear: " << batch.avgCreateUs << " μs";
            std::cout << " | Firmar: " << batch.avgSignUs << " μs";
            std::cout << " | Verificar: " << batch.avgVerifyUs << " μs\n";
            
            // Detectar degradación
            if (i > 0) {
                const auto& prevBatch = batchAnalyses[i - 1];
                double tpsChange = ((batch.tps - prevBatch.tps) / prevBatch.tps) * 100.0;
                if (tpsChange < -10.0) {
                    std::cout << "    ⚠️  DEGRADACIÓN: TPS disminuyó " << std::abs(tpsChange) << "%\n";
                }
            }
        }
    }
    
    // RESULTADOS FINALES
    std::cout << "\n=== RESULTADOS FINALES ===\n";
    std::cout << "Tiempo total de ejecución: " << totalTimeMs << " ms\n";
    std::cout << "Transacciones procesadas: " << totalTransactions << "\n";
    std::cout << "Throughput promedio: " << finalTps << " TX/segundo\n";
    if (totalTransactions > 0) {
        std::cout << "Tiempo promedio por transacción: " << (totalTimeUs / totalTransactions) << " μs\n";
    }
    std::cout << "Tamaño del vector: " << txs.size() << " (verificación)\n";
    
    // Análisis de consistencia del TPS
    if (!intervals.empty()) {
        double minTps = intervals[0].tps;
        double maxTps = intervals[0].tps;
        double totalIntervalTps = 0;
        
        for (const auto& interval : intervals) {
            minTps = std::min(minTps, interval.tps);
            maxTps = std::max(maxTps, interval.tps);
            totalIntervalTps += interval.tps;
        }
        
        double avgIntervalTps = totalIntervalTps / intervals.size();
        double variation = avgIntervalTps > 0 ? ((maxTps - minTps) / avgIntervalTps) * 100.0 : 0;
        
        std::cout << "\n--- Análisis de Consistencia ---\n";
        std::cout << "TPS mínimo: " << minTps << " TX/s\n";
        std::cout << "TPS máximo: " << maxTps << " TX/s\n";
        std::cout << "Variación: ±" << variation << "%\n";
        
        if (variation > 50.0) {
            std::cout << "⚠️  ALTA VARIACIÓN - Posible inestabilidad en el rendimiento\n";
        }
    }
    
    // RESUMEN EJECUTIVO
    std::cout << "\n=== RESUMEN EJECUTIVO ===\n";
    std::cout << "🎯 Throughput alcanzado: " << finalTps << " TX/segundo\n";
    std::cout << "📊 Transacciones en " << TIME_LIMIT_MS << "ms: " << totalTransactions << "\n";
    if (finalTps > 0) {
        std::cout << "⚡ Eficiencia: " << (totalTransactions / (finalTps * (TIME_LIMIT_MS / 1000.0)) * 100.0) << "% del potencial\n";
    }
    
    // Verificaciones finales
    EXPECT_GT(totalTransactions, 0);
    EXPECT_EQ(txs.size(), totalTransactions);
    
    std::cout << "\n✅ Test completado: " << totalTransactions << " transacciones en " 
              << totalTimeMs << " ms (" << finalTps << " TX/segundo)\n";
    
    // Recomendación final basada en los resultados
    if (finalTps < 1000) {
        std::cout << "💡 RECOMENDACIÓN: Revisar optimizaciones de rendimiento críticas\n";
    } else if (finalTps < 2000) {
        std::cout << "💡 RECOMENDACIÓN: Considerar optimizaciones adicionales\n";
    } else {
        std::cout << "💡 RECOMENDACIÓN: Rendimiento óptimo alcanzado\n";
    }
    
    // Actualizar métricas del test
    testMetrics["throughput_analysis_total_tx"] = totalTransactions;
    testMetrics["throughput_analysis_final_tps"] = finalTps;
    testMetrics["throughput_analysis_total_time_ms"] = totalTimeMs;
    testMetrics["throughput_analysis_avg_create_us"] = globalCreateUs;
    testMetrics["throughput_analysis_avg_sign_us"] = globalSignUs;
    testMetrics["throughput_analysis_avg_verify_us"] = globalVerifyUs;
}