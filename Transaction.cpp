#include "Transaction.hpp"
#include <sstream>
#include <iomanip>

/**
 * The Transaction constructor initializes member variables with default values.
 */
Transaction::Transaction() : from(""), to(""), amount(0.0), data(""), timestamp(0), hash(""), signature("") {};

Transaction::Transaction(const string& from, const string& to, double amount, const string& data) : from(from), to(to), amount(amount), data(data), signature("") {
    timestamp = time(nullptr);
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

// Setters
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
    string data = toString();
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.c_str(), data.size());
    SHA256_Final(hash, &sha256);
    
    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) { ss << hex << setw(2) << setfill('0') << (int)hash[i]; }
    
    this->hash = ss.str();
}

bool Transaction::isValid() const {
    if (amount <= 0) return false;
    if (from.empty() || to.empty()) return false;
    
    // Verificar que el hash calculado coincide con el almacenado
    Transaction temp(from, to, amount, data);
    temp.timestamp = timestamp; // Mantener el mismo timestamp
    temp.calculateHash();
    
    return temp.hash == hash;
}

string Transaction::toString() const {
    stringstream ss;
    ss << from << to << amount << data << timestamp;
    return ss.str();
}

bool Transaction::sign(const string& privateKey) {
    if (!CryptoUtils::isValidPrivateKey(privateKey)) return false;
    
    calculateHash(); // Asegurar que el hash esté calculado
    signature = CryptoUtils::signMessage(privateKey, hash);
    return !signature.empty();
}

bool Transaction::verifySignature() const {
    if (signature.empty()) return false;
    
    return CryptoUtils::verifySignature(from, hash, signature);
}

bool Transaction::involvesAddress(const string& address) const {
    return (from == address || to == address);
}
