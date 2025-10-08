#ifndef SIGNATURE_MANAGER_H
#define SIGNATURE_MANAGER_H

#include "Types.hpp"
#include "CryptoBase.hpp"

using namespace std;

class SignatureManager {
public:
    // Inicialización (solo una vez al inicio del programa)
    static bool initialize();
    
    // Firma
    static string signMessage(const string& privateKey, const string& message);
    static vector<uint8_t> signMessage(const vector<uint8_t>& privateKey, 
                                     const vector<uint8_t>& message);
    
    // Verificación - NOMBRES DIFERENTES para evitar ambigüedad
    static bool verifySignature(const string& publicKey, 
                              const vector<uint8_t>& message, 
                              const string& signatureBase64);
                
    static bool verifySignature(const vector<uint8_t>& publicKey,
                              const vector<uint8_t>& message,
                              const vector<uint8_t>& signature);
    
    static bool verifySignatureString(const string& publicKey, 
                                    const string& message, 
                                    const string& signatureBase64);
    
    static bool verifySignatureHex(const string& publicKey, 
                                 const string& messageHex, 
                                 const string& signatureBase64);
};

#endif // SIGNATURE_MANAGER_H