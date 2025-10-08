#ifndef KEY_MANAGER_H
#define KEY_MANAGER_H

#include "CryptoBase.hpp"
#include "Types.hpp"
#include <algorithm>

using namespace std;

class KeyManager {
public:
    // Generación de claves - ahora delega a CryptoBase
    static bool generateKeyPair(string& privateKey, string& publicKey);
    static bool generateKeyPair(vector<uint8_t>& privateKey, vector<uint8_t>& publicKey);
    
    // Derivación de clave pública desde privada
    static string derivePublicKey(const string& privateKeyBase64);
    
    // Validación simplificada
    static bool isValidPrivateKey(const string& privateKey);
    static bool isValidPublicKey(const string& publicKey);
    
    // ¡No más funciones complejas de OpenSSL!
};

#endif // KEY_MANAGER_H