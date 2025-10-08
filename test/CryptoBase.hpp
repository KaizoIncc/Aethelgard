#ifndef CRYPTO_BASE_H
#define CRYPTO_BASE_H

#include <vector>
#include <string>
#include <cstdint>
#include <sodium.h>
#include <sstream>
#include <iomanip>

using namespace std;

class CryptoBase {
public:
    // Inicialización (una sola vez al inicio)
    static bool initialize();
    
    // Hashing con libsodium (más rápido)
    static string sha256(const string& data);
    static string sha256(const vector<uint8_t>& data);
    static vector<uint8_t> sha256Bytes(const vector<uint8_t>& data);
    
    // Codificación/Decodificación (se mantienen igual - son eficientes)
    static string base64Encode(const vector<uint8_t>& data);
    static vector<uint8_t> base64Decode(const string& encoded);
    static string hexEncode(const vector<uint8_t>& data);
    static vector<uint8_t> hexDecode(const string& hexStr);
    
    // Generación de claves Ed25519 (NUEVO - mucho más simple)
    static bool generateKeyPair(string& privateKey, string& publicKey);
    static bool generateKeyPair(vector<uint8_t>& privateKey, vector<uint8_t>& publicKey);
    
    // Derivación de dirección (SIMPLIFICADO - solo SHA-256)
    static string getAddressFromPublicKey(const vector<uint8_t>& publicKey);
    
private:
    // Helpers internos para base64 (se mantienen igual)
    static string fastBase64Encode(const vector<uint8_t>& data);
    static vector<uint8_t> fastBase64Decode(const string& encoded);
};

#endif