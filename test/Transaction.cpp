#include "Transaction.hpp"

Transaction::Transaction() 
    : from(""), to(""), amount(0.0), data(""), timestamp(0), 
      hash(), signature(), publicKey() {}

Transaction::Transaction(const std::string& from, const std::string& to, 
                       double amount, const std::string& data)
    : from(from), to(to), amount(amount), data(data), 
      signature(), publicKey() {
    
    // Validación inicial exhaustiva
    if (from.empty() || to.empty()) {
        throw std::invalid_argument("From and to addresses cannot be empty");
    }
    
    if (amount <= 0) {
        throw std::invalid_argument("Amount must be positive");
    }
    
    if (amount < 1e-8) {
        throw std::invalid_argument("Amount below minimum limit (1e-8)");
    }
    
    if (amount > 1e9) {
        throw std::invalid_argument("Amount exceeds maximum limit (1e9)");
    }
    
    // Validar formato de direcciones en el constructor
    if (!isValidAddressFormat(from)) {
        throw std::invalid_argument("Invalid 'from' address format");
    }
    
    if (!isValidAddressFormat(to)) {
        throw std::invalid_argument("Invalid 'to' address format");
    }
    
    // No permitir transacciones a uno mismo
    if (from == to) {
        throw std::invalid_argument("Cannot create transaction to self");
    }
    
    // Establecer timestamp actual
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    timestamp = now;
    
    // Calcular hash inicial
    calculateHash();
}

// Getters
std::vector<uint8_t> Transaction::getHash() const { return hash; }
std::string Transaction::getHashHex() const { 
    return CryptoBase::bytesToHex(hash); 
}

std::string Transaction::getFrom() const { return from; }
std::string Transaction::getTo() const { return to; }
double Transaction::getAmount() const { return amount; }
std::string Transaction::getData() const { return data; }
std::time_t Transaction::getTimestamp() const { return timestamp; }

std::vector<uint8_t> Transaction::getSignature() const { return signature; }
std::string Transaction::getSignatureBase64() const { 
    return CryptoBase::base64Encode(signature); 
}

std::vector<uint8_t> Transaction::getPublicKey() const { return publicKey; }
std::string Transaction::getPublicKeyBase64() const { 
    return CryptoBase::base64Encode(publicKey); 
}

// Setters
// Setters (solo para deserialización)
void Transaction::setHash(const std::vector<uint8_t>& newHash) { hash = newHash; }
void Transaction::setSignature(const std::vector<uint8_t>& newSignature) { signature = newSignature; }
void Transaction::setPublicKey(const std::vector<uint8_t>& newPublicKey) { publicKey = newPublicKey; }
void Transaction::setTimestamp(std::time_t newTimestamp) { timestamp = newTimestamp; }

// Helper Functions
void Transaction::calculateHash() {
    std::string dataForHash = stringForHash();
    
    if (dataForHash.empty()) {
        throw std::runtime_error("Cannot calculate hash for empty transaction data");
    }
    
    // Calcular hash SHA-256 con libsodium
    std::vector<uint8_t> hash_bytes(crypto_hash_sha256_BYTES);
    
    int result = crypto_hash_sha256(
        hash_bytes.data(), 
        reinterpret_cast<const unsigned char*>(dataForHash.c_str()), 
        dataForHash.size()
    );
    
    if (result != 0) {
        throw std::runtime_error("Failed to calculate transaction hash");
    }
    
    this->hash = hash_bytes;
}

std::string Transaction::stringForHash() const {
    std::stringstream ss;
    ss << from << to << amount << data << timestamp;
    
    std::string result = ss.str();
    if (result.empty()) {
        throw std::runtime_error("Transaction data for hash is empty");
    }
    
    return result;
}

bool Transaction::sign(const std::vector<uint8_t>& privateKey) {
    // Validar clave privada
    if (privateKey.size() != PRIVATE_KEY_SIZE) {
        std::cerr << "Error: Invalid private key size for signing: " 
                  << privateKey.size() << " (expected: " << PRIVATE_KEY_SIZE << ")" << std::endl;
        return false;
    }
    
    // Verificar que la clave privada no sea toda ceros
    bool allZeros = std::all_of(privateKey.begin(), privateKey.end(), [](uint8_t b) { return b == 0; });
    if (allZeros) {
        std::cerr << "Error: Private key is all zeros" << std::endl;
        return false;
    }
    
    // Asegurar que el hash esté calculado
    if (hash.empty()) {
        calculateHash();
    }
    
    // Derivar clave pública desde la privada
    std::vector<uint8_t> derivedPublicKey(PUBLIC_KEY_SIZE);
    if (!KeyManager::derivePublicKey(privateKey, derivedPublicKey)) {
        std::cerr << "Error: Failed to derive public key from private key" << std::endl;
        return false;
    }
    
    // Verificar que la dirección derivada coincide con 'from'
    std::string derivedAddress = AddressManager::getAddressFromPublicKey(derivedPublicKey);
    
    if (derivedAddress != from) {
        std::cerr << "Error: Derived address '" << derivedAddress 
                  << "' does not match 'from' address '" << from << "'" << std::endl;
        CryptoBase::secureClean(derivedPublicKey);
        return false;
    }
    
    // Firmar el hash de la transacción
    std::vector<uint8_t> newSignature(SIGNATURE_SIZE);
    if (!SignatureManager::signMessage(privateKey, hash, newSignature)) {
        std::cerr << "Error: Failed to sign transaction hash" << std::endl;
        CryptoBase::secureClean(derivedPublicKey);
        CryptoBase::secureClean(newSignature);
        return false;
    }
    
    // Actualizar miembros
    signature = newSignature;
    publicKey = derivedPublicKey;
    
    return true;
}

bool Transaction::signFromEncoded(const std::string& privateKeyBase64) {
    if (privateKeyBase64.empty()) {
        std::cerr << "Error: Empty private key provided for signing" << std::endl;
        return false;
    }
    
    std::vector<uint8_t> privateKey;
    try {
        privateKey = CryptoBase::base64Decode(privateKeyBase64);
    } catch (const std::exception& e) {
        std::cerr << "Error decoding private key: " << e.what() << std::endl;
        return false;
    }
    
    bool success = sign(privateKey);
    
    // Limpiar memoria sensible inmediatamente
    CryptoBase::secureClean(privateKey);
    
    return success;
}

bool Transaction::verifySignature() const {
    if (signature.empty()) {
        std::cerr << "Error: Cannot verify empty signature" << std::endl;
        return false;
    }
    
    if (publicKey.empty()) {
        std::cerr << "Error: Cannot verify signature without public key" << std::endl;
        return false;
    }
    
    if (hash.empty()) {
        std::cerr << "Error: Cannot verify signature without transaction hash" << std::endl;
        return false;
    }
    
    // Verificar que la clave pública sea válida
    if (publicKey.size() != PUBLIC_KEY_SIZE) {
        std::cerr << "Error: Invalid public key size for verification: " 
                  << publicKey.size() << std::endl;
        return false;
    }
    
    // Verificar que la firma sea válida
    if (signature.size() != SIGNATURE_SIZE) {
        std::cerr << "Error: Invalid signature size for verification: " 
                  << signature.size() << std::endl;
        return false;
    }
    
    // Verificar la firma usando SignatureManager
    bool isValid = SignatureManager::verifySignature(publicKey, hash, signature);
    
    if (!isValid) {
        std::cerr << "Warning: Transaction signature verification failed" << std::endl;
    }
    
    return isValid;
}

bool Transaction::isValid() const {
    // Validar cantidad
    if (!validateAmount()) {
        std::cerr << "Error: Transaction amount validation failed" << std::endl;
        return false;
    }
    
    // Validar direcciones
    if (!validateAddresses()) {
        std::cerr << "Error: Transaction addresses validation failed" << std::endl;
        return false;
    }
    
    // Validar timing
    if (!validateTiming()) {
        std::cerr << "Error: Transaction timing validation failed" << std::endl;
        return false;
    }
    
    // La transacción debe estar firmada y la firma debe ser válida
    if (signature.empty() || publicKey.empty()) {
        std::cerr << "Error: Transaction is not signed" << std::endl;
        return false;
    }
    
    if (!verifySignature()) {
        std::cerr << "Error: Transaction signature is invalid" << std::endl;
        return false;
    }
    
    // Verificar que el hash calculado coincide con el almacenado
    Transaction temp(from, to, amount, data);
    temp.setTimestamp(timestamp);
    temp.calculateHash();
    
    bool hashValid = (temp.hash == hash);
    if (!hashValid) {
        std::cerr << "Error: Transaction hash mismatch" << std::endl;
        std::cerr << "Stored hash: " << getHashHex() << std::endl;
        std::cerr << "Calculated hash: " << temp.getHashHex() << std::endl;
    }
    
    return hashValid;
}

bool Transaction::validateAmount() const {
    if (amount <= 0) {
        std::cerr << "Error: Transaction amount must be positive" << std::endl;
        return false;
    }
    
    if (amount > 1e9) {
        std::cerr << "Error: Transaction amount exceeds maximum limit" << std::endl;
        return false;
    }
    
    if (amount < 1e-8) {
        std::cerr << "Error: Transaction amount below minimum limit" << std::endl;
        return false;
    }
    
    // Verificar que no sea NaN o infinito
    if (std::isnan(amount) || std::isinf(amount)) {
        std::cerr << "Error: Transaction amount is not a valid number" << std::endl;
        return false;
    }
    
    return true;
}

bool Transaction::validateAddresses() const {
    if (from.empty() || to.empty()) {
        std::cerr << "Error: Transaction addresses cannot be empty" << std::endl;
        return false;
    }
    
    if (from == to) {
        std::cerr << "Error: Cannot send transaction to self" << std::endl;
        return false;
    }
    
    if (!isValidAddressFormat(from)) {
        std::cerr << "Error: Invalid 'from' address format: " << from << std::endl;
        return false;
    }
    
    if (!isValidAddressFormat(to)) {
        std::cerr << "Error: Invalid 'to' address format: " << to << std::endl;
        return false;
    }
    
    return true;
}

bool Transaction::validateTiming() const {
    auto now = std::chrono::system_clock::now().time_since_epoch();
    auto current_time = std::chrono::duration_cast<std::chrono::seconds>(now).count();
    
    // La transacción no puede estar en el futuro (con margen de 2 minutos para sincronización)
    if (timestamp > current_time + 120) {
        std::cerr << "Error: Transaction timestamp is in the future" << std::endl;
        return false;
    }
    
    // La transacción no puede ser demasiado antigua (más de 1 año)
    const int64_t one_year_seconds = 365 * 24 * 60 * 60;
    if (timestamp < current_time - one_year_seconds) {
        std::cerr << "Error: Transaction is too old" << std::endl;
        return false;
    }
    
    return true;
}

bool Transaction::involvesAddress(const std::string& address) const {
    if (address.empty()) {
        return false;
    }
    
    if (!isValidAddressFormat(address)) {
        return false;
    }
    
    return (from == address || to == address);
}

// Helper privado para validación de formato de dirección
bool Transaction::isValidAddressFormat(const std::string& address) const {
    // Validar longitud exacta (40 caracteres para dirección Ethereum-style)
    if (address.length() != 40) {
        return false;
    }
    
    // Verificar que solo contengan caracteres hexadecimales
    auto isHexChar = [](char c) {
        return std::isxdigit(static_cast<unsigned char>(c)) != 0;
    };
    
    return std::all_of(address.begin(), address.end(), isHexChar);
}

std::string Transaction::toString() const {
    std::stringstream ss;
    ss << "Transaction{"
       << "from: " << from
       << ", to: " << to
       << ", amount: " << amount
       << ", timestamp: " << timestamp
       << ", hash: " << getHashHex().substr(0, 16) + "..."
       << "}";
    return ss.str();
}

std::string Transaction::toDebugString() const {
    std::stringstream ss;
    ss << "Transaction{\n"
       << "  from: " << from << "\n"
       << "  to: " << to << "\n"
       << "  amount: " << amount << "\n"
       << "  data: " << (data.empty() ? "[empty]" : "[present]") << "\n"
       << "  timestamp: " << timestamp << "\n"
       << "  hash: " << getHashHex() << "\n"
       << "  signature: " << (signature.empty() ? "[none]" : "[present]") << "\n"
       << "  publicKey: " << (publicKey.empty() ? "[none]" : "[present]") << "\n"
       << "  valid: " << (isValid() ? "true" : "false") << "\n"
       << "}";
    return ss.str();
}