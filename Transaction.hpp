#ifndef TRANSACTION_H
#define TRANSACTION_H

#include "Utils.hpp"
#include <string>
#include <vector>
#include <ctime>
#include <openssl/sha.h>

using namespace std;

class Transaction {
private:
    string hash;
    string from;
    string to;
    double amount;
    string data;
    time_t timestamp;
    string signature;

public:
    /**
     * The Transaction constructor initializes the transaction details, sets the timestamp, and calculates
     * the hash value.
     * 
     * @param from The `from` parameter in the `Transaction` constructor is a `const string&` type, which
     * represents the sender's address or identifier in a transaction.
     * @param to The `to` parameter in the `Transaction` constructor represents the recipient or
     * destination of the transaction. It is a `const string&` type, meaning it is a constant reference to
     * a string that cannot be modified within the constructor.
     * @param amount The `amount` parameter in the `Transaction` constructor represents the value of the
     * transaction, typically denoting the amount of currency or assets being transferred from the `from`
     * account to the `to` account.
     * @param data The `data` parameter in the `Transaction` constructor likely represents additional
     * information or metadata associated with the transaction. This could include details such as a
     * description of the transaction, a reference number, or any other relevant information that needs to
     * be stored along with the transaction data.
     */
    Transaction(const string& from, const string& to, double amount, const string& data = "");
    
    // Getters
    /**
     * This function returns the hash value of a transaction.
     * 
     * @return The `hash` member variable of the `Transaction` class is being returned.
     */
    string getHash() const;

    /**
     * This function returns the value of the "from" attribute in a Transaction object.
     * 
     * @return The `from` attribute of the `Transaction` object is being returned as a string.
     */
    string getFrom() const;
    
    /**
     * This function returns the value of the "to" attribute in a Transaction object.
     * 
     * @return The `to` attribute of the Transaction object is being returned as a string.
     */
    string getTo() const;

    /**
     * This function returns the amount of the transaction.
     * 
     * @return The `amount` variable is being returned.
     */
    double getAmount() const;
    
    /**
     * This function returns the data stored in the Transaction object as a string.
     * 
     * @return The `data` member variable of the `Transaction` class is being returned.
     */
    string getData() const;
    
    /**
     * This function returns the timestamp of a transaction.
     * 
     * @return The `timestamp` member variable of the `Transaction` class is being returned.
     */
    time_t getTimestamp() const;

    /**
     * The function `getSignature` returns the signature of a transaction.
     * 
     * @return The `signature` string is being returned.
     */
    string getSignature() const;
    
    /**
     * The function `calculateHash` calculates the SHA-256 hash of the transaction data and stores
     * it as a hexadecimal string.
     */
    void calculateHash();
    
    /**
     * The function `isValid` checks if a transaction is valid based on the amount, sender,
     * receiver, and hash.
     * 
     * @return The `isValid()` function is returning a boolean value. It will return `true` if the
     * transaction is considered valid based on the conditions specified in the function, and `false`
     * otherwise.
     */
    bool isValid() const;
    
    /**
     * The toString function in the Transaction class converts the transaction details to a string format.
     * 
     * @return The `toString` function is returning a concatenated string of the `from`, `to`, `amount`,
     * `data`, and `timestamp` member variables of the `Transaction` class. The values of these variables
     * are being streamed into a `stringstream` object `ss`, and then the concatenated string is
     * obtained using `ss.str()` and returned.
     */
    string toString() const;
    
    /**
     * The `sign` function signs a transaction using a private key after validating it and
     * calculating the hash.
     * 
     * @param privateKey The `privateKey` parameter is a string that represents the private key used for
     * signing the transaction. It is passed to the `sign` method of the `Transaction` class to sign the
     * transaction data.
     * 
     * @return The `sign` method returns a boolean value. It returns `true` if the signature is
     * successfully generated and not empty, and `false` otherwise.
     */
    bool sign(const string& privateKey);
    
    /**
     * The function `verifySignature` checks if a transaction signature is valid using CryptoUtils.
     * 
     * @return The `verifySignature` function is returning a boolean value. It returns `false` if the
     * `signature` is empty, and otherwise it calls the `CryptoUtils::verifySignature` function with the
     * `from`, `hash`, and `signature` parameters and returns the result of that function call.
     */
    bool verifySignature() const;
};

#endif // TRANSACTION_H