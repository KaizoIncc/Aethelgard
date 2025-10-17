# Compilador y flags
CXX = g++
CXXFLAGS = -std=c++17 -pthread -Wno-deprecated-declarations -I. -g
LIBS = -lgtest -lgtest_main -lsodium -lz

# Archivos fuente comunes - CORREGIDO
COMMON_SRCS = CryptoBase.cpp KeyManager.cpp SignatureManager.cpp AddressManager.cpp Types.hpp
BLOCK_HEADER_SRCS = BlockHeader.cpp
BLOCK_SRCS = Block.cpp $(BLOCK_HEADER_SRCS) Transaction.cpp $(COMMON_SRCS)
TRANSACTION_SRCS = Transaction.cpp $(COMMON_SRCS)
BLOCKCHAIN_STORAGE_SRCS = BlockchainStorage.cpp $(BLOCK_SRCS)
MESSAGE_SRCS = Message.cpp
PEER_MANAGER_SRCS = PeerManager.cpp
PEER_CONNECTION_SRCS = PeerConnection.cpp $(MESSAGE_SRCS) $(PEER_MANAGER_SRCS)

# Targets de tests - AGREGADOS LOS NUEVOS TESTS
TEST_TARGETS = test_Block test_BlockHeader test_CryptoBase test_KeyManager test_SignatureManager test_AddressManager test_Transaction

# Mapeo de archivos de test a ejecutables
TEST_EXECUTABLES = $(TEST_TARGETS)

# Reglas de compilación para cada test - CORREGIDAS LAS DEPENDENCIAS

# Tests originales
test_Block: test_Block.cpp $(BLOCK_SRCS)
	$(CXX) $(CXXFLAGS) test_Block.cpp $(BLOCK_SRCS) $(LIBS) -o $@

test_BlockHeader: test_BlockHeader.cpp $(BLOCK_HEADER_SRCS) $(COMMON_SRCS)
	$(CXX) $(CXXFLAGS) test_BlockHeader.cpp $(BLOCK_HEADER_SRCS) $(COMMON_SRCS) $(LIBS) -o $@

test_CryptoBase: test_CryptoBase.cpp $(COMMON_SRCS)
	$(CXX) $(CXXFLAGS) test_CryptoBase.cpp $(COMMON_SRCS) $(LIBS) -o $@

test_KeyManager: test_KeyManager.cpp $(COMMON_SRCS)
	$(CXX) $(CXXFLAGS) test_KeyManager.cpp $(COMMON_SRCS) $(LIBS) -o $@

test_SignatureManager: test_SignatureManager.cpp $(COMMON_SRCS)
	$(CXX) $(CXXFLAGS) test_SignatureManager.cpp $(COMMON_SRCS) $(LIBS) -o $@

test_AddressManager: test_AddressManager.cpp $(COMMON_SRCS)
	$(CXX) $(CXXFLAGS) test_AddressManager.cpp $(COMMON_SRCS) $(LIBS) -o $@

test_Transaction: test_Transaction.cpp $(TRANSACTION_SRCS)
	$(CXX) $(CXXFLAGS) test_Transaction.cpp $(TRANSACTION_SRCS) $(LIBS) -o $@

# Reglas principales
all: $(TEST_TARGETS)

build: all

test: all
	@echo "Ejecutando todos los tests..."
	@for test in $(TEST_TARGETS); do \
		echo "=== Ejecutando $$test ==="; \
		./$$test || exit 1; \
		echo ""; \
	done
	@echo "Todos los tests pasaron correctamente!"

# Nueva regla para ejecutar un test específico con filtro
# Uso: make test-file TEST_FILE=testHola TEST_NAME=DecirHola
test-file:
ifndef TEST_FILE
	$(error TEST_FILE no está definido. Uso: make test-file TEST_FILE=nombreArchivo TEST_NAME=nombreTest)
endif
ifndef TEST_NAME
	$(error TEST_NAME no está definido. Uso: make test-file TEST_FILE=nombreArchivo TEST_NAME=nombreTest)
endif
	@echo "Compilando $(TEST_FILE) si es necesario..."
	@if [ -f "$(TEST_FILE).cpp" ]; then \
		$(CXX) $(CXXFLAGS) $(TEST_FILE).cpp $(filter-out $(TEST_FILE).cpp,$(wildcard *.cpp)) $(LIBS) -o $(TEST_FILE) 2>/dev/null || true; \
		echo "Ejecutando test específico: $(TEST_FILE).$(TEST_NAME)"; \
		./$(TEST_FILE) --gtest_filter="$(TEST_NAME)" || (echo "Test falló o no se encontró"; exit 1); \
	else \
		echo "Error: Archivo $(TEST_FILE).cpp no encontrado"; \
		exit 1; \
	fi

# Versión simplificada para casos comunes
# Uso: make test-specific FILE=testHola NAME=HolaTest.DecirHola
test-specific:
ifndef FILE
	$(error FILE no está definido. Uso: make test-specific FILE=testHola NAME=HolaTest.DecirHola)
endif
ifndef NAME
	$(error NAME no está definido. Uso: make test-specific FILE=testHola NAME=HolaTest.DecirHola)
endif
	@echo "Compilando $(FILE) si es necesario..."
	@if [ -f "$(FILE).cpp" ]; then \
		$(CXX) $(CXXFLAGS) $(FILE).cpp $(filter-out $(FILE).cpp,$(wildcard *.cpp)) $(LIBS) -o $(FILE) 2>/dev/null || true; \
		echo "Ejecutando: $(FILE) --gtest_filter=$(NAME)"; \
		./$(FILE) --gtest_filter="$(NAME)" || (echo "Test falló o no se encontró"; exit 1); \
	else \
		echo "Error: Archivo $(FILE).cpp no encontrado"; \
		exit 1; \
	fi

# Reglas para ejecutar tests individuales
test-blockheader: testBlockHeader
	@echo "=== Ejecutando testBlockHeader ==="
	./testBlockHeader

test-cryptobase: testCryptoBase
	@echo "=== Ejecutando testCryptoBase ==="
	./testCryptoBase

test-keymanager: testKeyManager
	@echo "=== Ejecutando testKeyManager ==="
	./testKeyManager

test-signaturemanager: testSignatureManager
	@echo "=== Ejecutando testSignatureManager ==="
	./testSignatureManager

test-addressmanager: testAddressManager
	@echo "=== Ejecutando testAddressManager ==="
	./testAddressManager

test-transaction: testTransaction
	@echo "=== Ejecutando testTransaction ==="
	./testTransaction

# Reglas existentes
run-%: %
	@echo "=== Ejecutando $< ==="
	./$<

clean:
	rm -f $(TEST_TARGETS)

.PHONY: all build test clean test-file test-specific \
        test-blockheader test-cryptobase test-keymanager test-signaturemanager \
        test-addressmanager test-transaction