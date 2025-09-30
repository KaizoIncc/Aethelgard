# Compilador y flags
CXX = g++
CXXFLAGS = -std=c++17 -pthread -Wno-deprecated-declarations
LIBS = -lgtest -lgtest_main -lcrypto -lz

# Archivos fuente comunes
COMMON_SRCS = Utils.cpp
BLOCK_HEADER_SRCS = BlockHeader.cpp
BLOCK_SRCS = Block.cpp $(BLOCK_HEADER_SRCS) Transaction.cpp $(COMMON_SRCS)
TRANSACTION_SRCS = Transaction.cpp $(COMMON_SRCS)
BLOCKCHAIN_STORAGE_SRCS = BlockchainStorage.cpp $(BLOCK_SRCS)
MESSAGE_SRCS = Message.cpp
PEER_MANAGER_SRCS = PeerManager.cpp
PEER_CONNECTION_SRCS = PeerConnection.cpp $(MESSAGE_SRCS) $(PEER_MANAGER_SRCS)

# Targets de tests
TEST_TARGETS = testBlockClass testIntegratedBlockchain1 testTransactionClass testBlockchainStorageClass testBlockHeaderClass testMessageClass testPeerManagerClass testPeerConnectionClass

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

test-%: %
	@echo "=== Ejecutando $< ==="
	./$<

run-%: test-%
	@echo "Test $* completado"

clean:
	rm -f $(TEST_TARGETS)

.PHONY: all build test clean