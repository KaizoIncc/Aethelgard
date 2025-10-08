#ifndef ADDRESS_MANAGER_H
#define ADDRESS_MANAGER_H

#include "CryptoBase.hpp"
#include <algorithm>
#include <cctype>

using namespace std;

class AddressManager {
public:
    static string getAddressFromPublicKey(const string& publicKey);
    static string getAddressFromPublicKey(const vector<uint8_t>& publicKey);
    static string publicKeyToAddress(const string& publicKeyBase64);
    static bool isValidAddress(const string& address);
};

#endif // ADDRESS_MANAGER_H