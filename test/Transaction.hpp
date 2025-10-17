#ifndef TRANSACTION_H
#define TRANSACTION_H

#include "CryptoBase.hpp"
#include "SignatureManager.hpp"
#include "KeyManager.hpp"
#include "AddressManager.hpp"
#include <string>
#include <vector>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <cmath>
#include "Types.hpp"

class Transaction {
private:
    std::vector<uint8_t> hash;          // Hash binario de la transacción
    std::string from;                   // Dirección del emisor (hex)
    std::string to;                     // Dirección del receptor (hex)
    double amount;
    std::string data;                   // Datos adicionales (texto)
    std::time_t timestamp;
    std::vector<uint8_t> signature;     // Firma binaria
    std::vector<uint8_t> publicKey;     // Clave pública binaria

    
    void calculateHash();

public:
    // Constructor por defecto
    Transaction();
    
    // Constructor principal
    Transaction(const std::string& from, const std::string& to, 
                double amount, const std::string& data = "");
    
    // Permitir copia para serialización (pero con cuidado)
    Transaction(const Transaction&) = default;
    Transaction& operator=(const Transaction&) = default;
    
    // Getters
    std::vector<uint8_t> getHash() const;
    std::string getHashHex() const;
    std::string getFrom() const;
    std::string getTo() const;
    double getAmount() const;
    std::string getData() const;
    std::time_t getTimestamp() const;
    std::vector<uint8_t> getSignature() const;
    std::string getSignatureBase64() const;
    std::vector<uint8_t> getPublicKey() const;
    std::string getPublicKeyBase64() const;

    // Setters limitados solo para deserialización
    void setHash(const std::vector<uint8_t>& newHash);
    void setSignature(const std::vector<uint8_t>& newSignature);
    void setPublicKey(const std::vector<uint8_t>& newPublicKey);
    void setTimestamp(std::time_t newTimestamp);

    // Operaciones de firma y verificación
    bool sign(const std::vector<uint8_t>& privateKey);
    bool signFromEncoded(const std::string& privateKeyBase64);
    bool verifySignature() const;
    
    // Validación
    bool isValid() const;
    bool involvesAddress(const std::string& address) const;
    
    // Serialización
    std::string toString() const;
    std::string toDebugString() const;

    std::string stringForHash() const;

    // Helpers de validación interna
    bool validateAmount() const;
    bool validateAddresses() const;
    bool validateTiming() const;
    bool isValidAddressFormat(const std::string& address) const;
};

#endif // TRANSACTION_H