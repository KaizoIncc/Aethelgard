# Compilador y flags
CXX = g++
CXXFLAGS = -std=c++17 -pthread -Wno-deprecated-declarations
LIBS = -lgtest -lgtest_main -lsodium -lz

# Archivos fuente comunes
COMMON_SRCS = Utils.cpp CryptoBase.cpp KeyManager.cpp SignatureManager.cpp AddressManager.cpp
BLOCK_HEADER_SRCS = BlockHeader.cpp
BLOCK_SRCS = Block.cpp $(BLOCK_HEADER_SRCS) Transaction.cpp $(COMMON_SRCS)
TRANSACTION_SRCS = Transaction.cpp $(COMMON_SRCS)
BLOCKCHAIN_STORAGE_SRCS = BlockchainStorage.cpp $(BLOCK_SRCS)
MESSAGE_SRCS = Message.cpp
PEER_MANAGER_SRCS = PeerManager.cpp
PEER_CONNECTION_SRCS = PeerConnection.cpp $(MESSAGE_SRCS) $(PEER_MANAGER_SRCS)

# Targets de tests
TEST_TARGETS = testBlockClass testIntegratedBlockchain1 testTransactionClass testBlockchainStorageClass testBlockHeaderClass testMessageClass testPeerManagerClass testPeerConnectionClass

# Mapeo de archivos de test a ejecutables
TEST_EXECUTABLES = $(TEST_TARGETS)

# Reglas de compilación para cada test
testBlockClass: testBlockClass.cpp $(BLOCK_SRCS)
	$(CXX) $(CXXFLAGS) testBlockClass.cpp $(BLOCK_SRCS) $(LIBS) -o $@

testIntegratedBlockchain1: testIntegratedBlockchain1.cpp $(BLOCKCHAIN_STORAGE_SRCS)
	$(CXX) $(CXXFLAGS) testIntegratedBlockchain1.cpp $(BLOCKCHAIN_STORAGE_SRCS) $(LIBS) -o $@

testTransactionClass: testTransactionClass.cpp $(TRANSACTION_SRCS)
	$(CXX) $(CXXFLAGS) testTransactionClass.cpp $(TRANSACTION_SRCS) $(LIBS) -o $@

testBlockchainStorageClass: testBlockchainStorageClass.cpp $(BLOCKCHAIN_STORAGE_SRCS)
	$(CXX) $(CXXFLAGS) testBlockchainStorageClass.cpp $(BLOCKCHAIN_STORAGE_SRCS) $(LIBS) -o $@

testBlockHeaderClass: testBlockHeaderClass.cpp $(BLOCK_HEADER_SRCS)
	$(CXX) $(CXXFLAGS) testBlockHeaderClass.cpp $(BLOCK_HEADER_SRCS) $(LIBS) -o $@

testMessageClass: testMessageClass.cpp $(MESSAGE_SRCS)
	$(CXX) $(CXXFLAGS) testMessageClass.cpp $(MESSAGE_SRCS) $(LIBS) -o $@

testPeerManagerClass: testPeerManagerClass.cpp $(PEER_MANAGER_SRCS)
	$(CXX) $(CXXFLAGS) testPeerManagerClass.cpp $(PEER_MANAGER_SRCS) $(LIBS) -o $@

testPeerConnectionClass: testPeerConnectionClass.cpp $(PEER_CONNECTION_SRCS)
	$(CXX) $(CXXFLAGS) testPeerConnectionClass.cpp $(PEER_CONNECTION_SRCS) $(LIBS) -o $@

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

# Reglas existentes
test-%: %
	@echo "=== Ejecutando $< ==="
	./$<

run-%: test-%
	@echo "Test $* completado"

clean:
	rm -f $(TEST_TARGETS)

.PHONY: all build test clean test-file test-specific