cmake_minimum_required(VERSION 3.10)
project(BlockchainCore)

set(CMAKE_CXX_STANDARD 17)

# Encontrar OpenSSL - versión más específica
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

# Archivos fuente (asegúrate de incluir Utils.cpp que contiene CryptoUtils)
set(SOURCES
    src/Utils.cpp
    src/Transaction.cpp
    src/BlockHeader.cpp
    src/Block.cpp
)

# Archivos de cabecera
set(HEADERS
    include/Utils.hpp
    include/Transaction.hpp
    include/BlockHeader.hpp
    include/Block.hpp
)

# Biblioteca principal
add_library(BlockchainCore ${SOURCES} ${HEADERS})
target_include_directories(BlockchainCore PUBLIC include)

# Enlazar OpenSSL - versión simplificada y correcta
target_link_libraries(BlockchainCore OpenSSL::Crypto)

# Opcional: Configuraciones adicionales recomendadas
set_target_properties(BlockchainCore PROPERTIES
    CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON
)
