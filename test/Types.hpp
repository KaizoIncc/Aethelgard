#ifndef CRYPTO_TYPES_H
#define CRYPTO_TYPES_H

#include <cstdint>
#include <cstddef>

// -----------------------------------------------------------------------------------
// ---------------------------- Libsodium Types --------------------------------------
// -----------------------------------------------------------------------------------

// Constantes para Ed25519 (libsodium)
inline constexpr size_t PRIVATE_KEY_SIZE = 64;  // Clave privada completa de libsodium
inline constexpr size_t SEED_SIZE = 32; // Semilla
inline constexpr size_t PUBLIC_KEY_SIZE = 32; // Clave pública
inline constexpr size_t SIGNATURE_SIZE = 64; // Tamaño de la firma Ed25519
inline constexpr size_t SHA256_HASH_SIZE = 32; // Tamaño del hash SHA-256

// ==== CONSTANTES DE SERIALIZACION ====
inline constexpr uint32_t SERIALIZATION_VERSION = 1; // Versión de serialización
inline constexpr uint32_t BLOCK_MAGIC = 0xB10CDA7A; // Mágico para bloques
inline constexpr uint32_t TX_MAGIC = 0xDA7A123; // Mágico para transacciones

// ==== CONSTANTES DE DIRECCIONES ====
inline constexpr size_t ADDRESS_SIZE = 20;    // Dirección en bytes (20 bytes = 160 bits)
inline constexpr size_t ADDRESS_HEX_LENGTH = 40; // Dirección en hexadecimal (40 caracteres)

// ==== CONSTANTES DE BLOQUES ====
inline constexpr size_t MAX_TRANSACTIONS = 1000; // Límite de transacciones por bloque
inline constexpr size_t MAX_BLOCK_SIZE = 1024 * 1024; // 1MB límite de bloque

// ==== LÍMITES DE SEGURIDAD ====
inline constexpr size_t MAX_BLOCK_FILE_SIZE = 10 * 1024 * 1024; // 10MB
inline constexpr size_t MAX_TX_FILE_SIZE = 1 * 1024 * 1024;     // 1MB

// ============================================================
//  CONFIGURACIÓN DEL PROTOCOLO P2P
// ============================================================

// Network magic value - único para tu red
inline constexpr uint32_t NETWORK_MAGIC = 0xDAB5BFFA;

// Versión del protocolo
inline constexpr uint8_t PROTOCOL_VERSION = 1;

// Límites de tamaño
inline constexpr size_t MAX_PAYLOAD_SIZE = 4 * 1024 * 1024; // 4 MB máximo
inline constexpr size_t MESSAGE_HEADER_SIZE = 4 + 1 + 1 + 8; // magic + version + type + payload_len
inline constexpr size_t CHECKSUM_SIZE = 4; // CRC32

// Tamaños para handshake
inline constexpr size_t NODE_ID_SIZE = 32; // 256-bit node identifier
inline constexpr size_t NONCE_SIZE = 32;   // 256-bit nonce for handshake
inline constexpr size_t HANDSHAKE_TIMEOUT_MS = 10000; // 10 segundos timeout

// Límites de red
inline constexpr size_t MAX_PEERS = 1000;
inline constexpr size_t MAX_MESSAGE_QUEUE = 10000;

#endif // CRYPTO_TYPES_H