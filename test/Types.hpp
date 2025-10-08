#ifndef CRYPTO_TYPES_H
#define CRYPTO_TYPES_H

#include <vector>
#include <cstdint>

// -----------------------------------------------------------------------------------
// ---------------------------- Libsodium Types --------------------------------------
// -----------------------------------------------------------------------------------

// Constantes para Ed25519 (libsodium)
static constexpr size_t PRIVATE_KEY_SIZE = 64;  // Clave privada completa de libsodium
static constexpr size_t PRIVATE_SEED_SIZE = 32; // Semilla privada
static constexpr size_t PUBLIC_KEY_SIZE = 32;
static constexpr size_t SIGNATURE_SIZE = 64;

// ¡No más smart pointers complejos para OpenSSL!
// Libsodium maneja toda la memoria automáticamente

#endif // CRYPTO_TYPES_H