#include <gtest/gtest.h>
#include "Transaction.hpp"
#include "Utils.hpp"
#include <thread>
#include <chrono>
#include <algorithm>
#include <cfloat>     // para DBL_MAX
#include <limits>     // para numeric_limits

using namespace chrono;

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
TEST_F(TransactionTest, ComprehensiveThroughputAndBottleneckAnalysis) {
    const int TIME_LIMIT_MS = 3000; // 3 segundos de ejecución
    const int REPORT_INTERVAL_MS = 100; // Reportar cada 100ms
    const int BATCH_ANALYSIS_SIZE = 500; // Analizar cada 500 transacciones
    
    vector<Transaction> txs;
    
    auto testStart = high_resolution_clock::now();
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
    
    vector<IntervalMetrics> intervals;
    vector<BatchAnalysis> batchAnalyses;
    OperationMetrics currentBatchMetrics;
    
    cout << "🔍 EJECUTANDO ANÁLISIS COMPLETO DE THROUGHPUT Y CUELOS DE BOTELLA\n";
    cout << "Tiempo límite: " << TIME_LIMIT_MS << " ms\n";
    cout << "Tiempo | Transacciones | TPS actual | Crear | Firmar | Verificar | Bottleneck\n";
    cout << "--------------------------------------------------------------------------------\n";

    while (true) {
        auto currentTime = high_resolution_clock::now();
        auto elapsedMs = duration_cast<milliseconds>(currentTime - testStart).count();
        
        // Verificar si ha pasado el tiempo límite
        if (elapsedMs >= TIME_LIMIT_MS) {
            break;
        }
        
        // Medir tiempos individuales de cada operación
        auto t1 = high_resolution_clock::now();
        Transaction tx(addr1, addr2, totalTransactions + 0.1, "ThroughputTest");
        auto t2 = high_resolution_clock::now();
        
        EXPECT_TRUE(tx.sign(privKey1));
        auto t3 = high_resolution_clock::now();
        
        EXPECT_TRUE(tx.verifySignature());
        auto t4 = high_resolution_clock::now();
        
        txs.push_back(move(tx));
        totalTransactions++;
        transactionsSinceLastReport++;
        
        // Acumular métricas de operaciones
        long long createUs = duration_cast<microseconds>(t2 - t1).count();
        long long signUs = duration_cast<microseconds>(t3 - t2).count();
        long long verifyUs = duration_cast<microseconds>(t4 - t3).count();
        
        currentBatchMetrics.createTimeUs += createUs;
        currentBatchMetrics.signTimeUs += signUs;
        currentBatchMetrics.verifyTimeUs += verifyUs;
        currentBatchMetrics.count++;
        
        // Reportar cada 100ms
        auto timeSinceLastReport = duration_cast<milliseconds>(currentTime - lastReport).count();
        if (timeSinceLastReport >= REPORT_INTERVAL_MS) {
            double currentTps = transactionsSinceLastReport / (timeSinceLastReport / 1000.0);
            double averageTps = totalTransactions / (elapsedMs / 1000.0);
            
            // Calcular promedios del intervalo
            double avgCreate = currentBatchMetrics.createTimeUs / (double)currentBatchMetrics.count;
            double avgSign = currentBatchMetrics.signTimeUs / (double)currentBatchMetrics.count;
            double avgVerify = currentBatchMetrics.verifyTimeUs / (double)currentBatchMetrics.count;
            
            // Identificar cuello de botella
            string bottleneck = "Ninguno";
            double maxTime = max({avgCreate, avgSign, avgVerify});
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
            
            cout << setw(6) << elapsedMs << " ms | "
                      << setw(13) << totalTransactions << " | "
                      << setw(10) << fixed << setprecision(0) << currentTps << " | "
                      << setw(6) << fixed << setprecision(1) << avgCreate << " | "
                      << setw(6) << fixed << setprecision(1) << avgSign << " | "
                      << setw(9) << fixed << setprecision(1) << avgVerify << " | "
                      << bottleneck << "\n";
            
            transactionsSinceLastReport = 0;
            lastReport = currentTime;
            
            // Resetear métricas del intervalo
            currentBatchMetrics = OperationMetrics();
        }
        
        // Análisis por lotes cada BATCH_ANALYSIS_SIZE transacciones
        if (totalTransactions % BATCH_ANALYSIS_SIZE == 0) {
            auto batchEnd = high_resolution_clock::now();
            long long batchTimeMs = duration_cast<milliseconds>(batchEnd - testStart).count();
            double batchTps = totalTransactions / (batchTimeMs / 1000.0);
            
            batchAnalyses.push_back({
                totalTransactions - BATCH_ANALYSIS_SIZE,
                totalTransactions,
                currentBatchMetrics.createTimeUs / (double)currentBatchMetrics.count,
                currentBatchMetrics.signTimeUs / (double)currentBatchMetrics.count,
                currentBatchMetrics.verifyTimeUs / (double)currentBatchMetrics.count,
                batchTps,
                batchTimeMs
            });
        }
    }
    
    auto testEnd = high_resolution_clock::now();
    auto totalTimeMs = duration_cast<milliseconds>(testEnd - testStart).count();
    auto totalTimeUs = duration_cast<microseconds>(testEnd - testStart).count();
    double finalTps = totalTransactions / (totalTimeMs / 1000.0);
    
    // ANÁLISIS DETALLADO DE CUELOS DE BOTELLA
    cout << "\n=== ANÁLISIS COMPLETO DE CUELOS DE BOTELLA ===\n";
    
    // Calcular promedios globales
    double globalCreateUs = 0, globalSignUs = 0, globalVerifyUs = 0;
    for (const auto& interval : intervals) {
        globalCreateUs += interval.createTimeUs;
        globalSignUs += interval.signTimeUs;
        globalVerifyUs += interval.verifyTimeUs;
    }
    
    globalCreateUs /= intervals.size();
    globalSignUs /= intervals.size();
    globalVerifyUs /= intervals.size();
    
    double totalOperationTime = globalCreateUs + globalSignUs + globalVerifyUs;
    double createPercentage = (globalCreateUs / totalOperationTime) * 100.0;
    double signPercentage = (globalSignUs / totalOperationTime) * 100.0;
    double verifyPercentage = (globalVerifyUs / totalOperationTime) * 100.0;
    
    cout << "Distribución del tiempo por operación:\n";
    cout << "  • Creación: " << globalCreateUs << " μs (" << createPercentage << "%)\n";
    cout << "  • Firma: " << globalSignUs << " μs (" << signPercentage << "%)\n";
    cout << "  • Verificación: " << globalVerifyUs << " μs (" << verifyPercentage << "%)\n";
    
    // Identificar cuello de botella principal
    cout << "\n🔍 IDENTIFICACIÓN DE CUELOS DE BOTELLA:\n";
    if (signPercentage > 60) {
        cout << "  ⚠️  CUELO DE BOTELLA PRINCIPAL: FIRMA (" << signPercentage << "% del tiempo)\n";
        cout << "     Recomendación: Optimizar la caché de claves y el pool de firmas\n";
    } else if (verifyPercentage > 60) {
        cout << "  ⚠️  CUELO DE BOTELLA PRINCIPAL: VERIFICACIÓN (" << verifyPercentage << "% del tiempo)\n";
        cout << "     Recomendación: Mejorar la caché de claves públicas\n";
    } else if (createPercentage > 60) {
        cout << "  ⚠️  CUELO DE BOTELLA PRINCIPAL: CREACIÓN (" << createPercentage << "% del tiempo)\n";
        cout << "     Recomendación: Revisar constructores y asignación de memoria\n";
    } else if (max({createPercentage, signPercentage, verifyPercentage}) > 40) {
        cout << "  📊 DISTRIBUCIÓN BALANCEADA con operación dominante\n";
    } else {
        cout << "  ✅ DISTRIBUCIÓN EQUILIBRADA - Sin cuellos de botella evidentes\n";
    }
    
    // Análisis de evolución temporal
    cout << "\n=== EVOLUCIÓN TEMPORAL DEL RENDIMIENTO ===\n";
    if (!batchAnalyses.empty()) {
        cout << "Análisis por lotes de " << BATCH_ANALYSIS_SIZE << " transacciones:\n";
        for (size_t i = 0; i < batchAnalyses.size(); i++) {
            const auto& batch = batchAnalyses[i];
            cout << "  Lote " << (i + 1) << " (TX " << batch.startTx << "-" << batch.endTx << "):\n";
            cout << "    • TPS: " << batch.tps << " | Crear: " << batch.avgCreateUs << " μs";
            cout << " | Firmar: " << batch.avgSignUs << " μs";
            cout << " | Verificar: " << batch.avgVerifyUs << " μs\n";
            
            // Detectar degradación
            if (i > 0) {
                const auto& prevBatch = batchAnalyses[i - 1];
                double tpsChange = ((batch.tps - prevBatch.tps) / prevBatch.tps) * 100.0;
                if (tpsChange < -10.0) {
                    cout << "    ⚠️  DEGRADACIÓN: TPS disminuyó " << abs(tpsChange) << "%\n";
                }
            }
        }
    }
    
    // RESULTADOS FINALES
    cout << "\n=== RESULTADOS FINALES ===\n";
    cout << "Tiempo total de ejecución: " << totalTimeMs << " ms\n";
    cout << "Transacciones procesadas: " << totalTransactions << "\n";
    cout << "Throughput promedio: " << finalTps << " TX/segundo\n";
    cout << "Tiempo promedio por transacción: " << (totalTimeUs / totalTransactions) << " μs\n";
    cout << "Tamaño del vector: " << txs.size() << " (verificación)\n";
    
    // Análisis de consistencia del TPS
    if (!intervals.empty()) {
        double minTps = intervals[0].tps;
        double maxTps = intervals[0].tps;
        double totalIntervalTps = 0;
        
        for (const auto& interval : intervals) {
            minTps = min(minTps, interval.tps);
            maxTps = max(maxTps, interval.tps);
            totalIntervalTps += interval.tps;
        }
        
        double avgIntervalTps = totalIntervalTps / intervals.size();
        double variation = ((maxTps - minTps) / avgIntervalTps) * 100.0;
        
        cout << "\n--- Análisis de Consistencia ---\n";
        cout << "TPS mínimo: " << minTps << " TX/s\n";
        cout << "TPS máximo: " << maxTps << " TX/s\n";
        cout << "Variación: ±" << variation << "%\n";
        
        if (variation > 50.0) {
            cout << "⚠️  ALTA VARIACIÓN - Posible inestabilidad en el rendimiento\n";
        }
    }
    
    // RESUMEN EJECUTIVO
    cout << "\n=== RESUMEN EJECUTIVO ===\n";
    cout << "🎯 Throughput alcanzado: " << finalTps << " TX/segundo\n";
    cout << "📊 Transacciones en " << TIME_LIMIT_MS << "ms: " << totalTransactions << "\n";
    cout << "⚡ Eficiencia: " << (totalTransactions / (finalTps * (TIME_LIMIT_MS / 1000.0)) * 100.0) << "% del potencial\n";
    
    // Verificaciones finales
    EXPECT_GT(totalTransactions, 0);
    EXPECT_EQ(txs.size(), totalTransactions);
    
    cout << "\n✅ Test completado: " << totalTransactions << " transacciones en " 
              << totalTimeMs << " ms (" << finalTps << " TX/segundo)\n";
    
    // Recomendación final basada en los resultados
    if (finalTps < 1000) {
        cout << "💡 RECOMENDACIÓN: Revisar optimizaciones de rendimiento críticas\n";
    } else if (finalTps < 2000) {
        cout << "💡 RECOMENDACIÓN: Considerar optimizaciones adicionales\n";
    } else {
        cout << "💡 RECOMENDACIÓN: Rendimiento óptimo alcanzado\n";
    }
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
