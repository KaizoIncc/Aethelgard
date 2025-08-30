cmake_minimum_required(VERSION 3.10)
project(BlockchainCore)

set(CMAKE_CXX_STANDARD 17)

# Encontrar OpenSSL
find_package(OpenSSL REQUIRED)

# Archivos fuente
set(SOURCES
    src/Transaction.cpp
    src/BlockHeader.cpp
    src/Block.cpp
)

# Archivos de cabecera
set(HEADERS
    include/Transaction.h
    include/BlockHeader.h
    include/Block.h
)

# Biblioteca principal
add_library(BlockchainCore ${SOURCES} ${HEADERS})
target_include_directories(BlockchainCore PUBLIC include)
target_link_libraries(BlockchainCore OpenSSL::SSL OpenSSL::Crypto)