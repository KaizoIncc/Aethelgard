#include "Transaction.hpp"
#include <sodium.h>
#include <iostream>

using namespace std;

/**
 * The Transaction constructor initializes member variables with default values.
 */
Transaction::Transaction() : from(""), to(""), amount(0.0), data(""), timestamp(0), hash(""), signature("") {};

Transaction::Transaction(const string& from, const string& to, double amount, const string& data) : from(from), to(to), amount(amount), data(data), signature(""), publicKey("") {
    auto now = chrono::duration_cast<chrono::milliseconds>(
        chrono::system_clock::now().time_since_epoch()
    ).count();
    timestamp = now;
    calculateHash();
}

// Getters
string Transaction::getHash() const { return hash; }
string Transaction::getFrom() const { return from; }
string Transaction::getTo() const { return to; }
double Transaction::getAmount() const { return amount; }
string Transaction::getData() const { return data; }
time_t Transaction::getTimestamp() const { return timestamp; }
string Transaction::getSignature() const { return signature; }
string Transaction::getPublicKey() const { return publicKey; }

// Setters
void Transaction::setHash(const string& hash) { this->hash = hash; }
void Transaction::setTimestamp(time_t timestamp) { this->timestamp = timestamp; }
void Transaction::setSignature(const string& signature) { this->signature = signature; }
void Transaction::setFrom(const string& from) { this->from = from; }
void Transaction::setTo(const string& to) { this->to = to; }
void Transaction::setAmount(double amount) { this->amount = amount; }
void Transaction::setData(const string& data) { this->data = data; }

// Helper Functions
void Transaction::calculateHash() {
    string data = stringForHash();
    
    // ¡VERSIÓN ACTUALIZADA CON LIBSODIUM!
    vector<uint8_t> hash_bytes(crypto_hash_sha256_BYTES); // 32 bytes
    
    // Calcular hash SHA-256 con libsodium
    crypto_hash_sha256(hash_bytes.data(), 
                      reinterpret_cast<const unsigned char*>(data.c_str()), 
                      data.size());
    
    // Convertir a hexadecimal
    stringstream ss;
    for (uint8_t byte : hash_bytes) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(byte);
    }
    
    this->hash = ss.str();
}

bool Transaction::isValid() const {
    if (amount <= 0) return false;
    if (amount > 1e9) return false;           // límite superior arbitrario
    if (amount < 1e-8) return false;          // límite inferior arbitrario

    if (from.empty() || to.empty()) return false;
    if (from == to) return false;

    // Validar formato de direcciones
    if (!CryptoUtils::isValidAddress(from)) return false;
    if (!CryptoUtils::isValidAddress(to)) return false;

    // La transacción debe estar firmada
    if (signature.empty() || publicKey.empty()) return false;
    if (!verifySignature()) return false;
    
    // Verificar que el hash calculado coincide con el almacenado
    Transaction temp(from, to, amount, data);
    temp.timestamp = timestamp; // Mantener el mismo timestamp
    temp.calculateHash();
    
    return temp.hash == hash;
}

string Transaction::toString() const {
    stringstream ss;
    ss << from << to << amount << data << timestamp << hash << signature;
    return ss.str();
}

string Transaction::stringForHash() const {
    stringstream ss;
    ss << from << to << amount << data << timestamp;
    return ss.str();
}

bool Transaction::sign(const string& privateKey) {
    if (!CryptoUtils::isValidPrivateKey(privateKey)) return false;

    // Derivar clave pública y dirección a partir de la privateKey
    string derivedPubKey = CryptoUtils::derivePublicKey(privateKey);
    string derivedAddr = CryptoUtils::publicKeyToAddress(derivedPubKey);

    // Solo permitimos firmar si la dirección coincide con "from"
    if (derivedAddr != from) return false;

    // No permitimos transacciones de loop
    if (from == to) return false;

    calculateHash(); // asegurar que el hash esté actualizado
    signature = CryptoUtils::signMessage(privateKey, hash);
    publicKey = derivedPubKey; // guardamos la pubkey para la verificación

    return !signature.empty();
}

bool Transaction::verifySignature() const {
    if (signature.empty() || publicKey.empty() || hash.empty()) {
        return false;
    }
    
    // Verificar que la clave pública sea válida
    if (!CryptoUtils::isValidPublicKey(publicKey)) {
        return false;
    }
    
    // Usar la versión específica para hashes hexadecimales
    return CryptoUtils::verifySignatureHex(publicKey, hash, signature);
}

bool Transaction::involvesAddress(const string& address) const {
    return (from == address || to == address);
}