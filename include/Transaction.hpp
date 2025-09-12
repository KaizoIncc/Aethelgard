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

    Transaction();
    
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

    // Setters
    /**
     * The function `setHash` in the `Transaction` class sets the hash value to the provided string.
     * 
     * @param hash The `hash` parameter is a string that represents the hash value to be set for the
     * transaction.
     */
    void setHash(const string& hash);
    
    /**
     * The function `setTimestamp` sets the timestamp of a transaction.
     * 
     * @param timestamp The `timestamp` parameter is a variable of type `time_t` that represents the time
     * at which a transaction occurred.
     */
    void setTimestamp(time_t timestamp);

    /**
     * This function sets the signature of a transaction.
     * 
     * @param signature The `signature` parameter is a string that represents the signature of a
     * transaction.
     */
    void setSignature(const string& signature);

    /**
     * The function sets the "from" attribute of a Transaction object to the provided string value.
     * 
     * @param from The `setFrom` function in the `Transaction` class is used to set the value of the `from`
     * member variable to the provided `from` parameter. This function takes a constant reference to a
     * string as its parameter.
     */
    void setFrom(const string& from);

    /**
     * This function sets the "to" attribute of a Transaction object to the provided string.
     * 
     * @param to The `to` parameter in the `Transaction::setTo` function is a reference to a constant
     * string.
     */
    void setTo(const string& to);

    /**
     * The function sets the amount for a transaction.
     * 
     * @param amount The `amount` parameter is a double type variable that represents the value to be set
     * for the transaction amount in the `Transaction` class.
     */
    void setAmount(double amount);

    /**
     * The function `setData` in the `Transaction` class sets the data member to the provided string.
     * 
     * @param data The `data` parameter in the `setData` function is a constant reference to a string.
     */
    void setData(const string& data);
    
    // Helper functions
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

    /**
     * The function `involvesAddress` checks if a transaction involves a specific address.
     * 
     * @param address The `address` parameter is a reference to a constant string.
     * 
     * @return The function `involvesAddress` returns a boolean value indicating whether the transaction
     * involves a specific address. It checks if the address provided is either the sender (`from`) or the
     * receiver (`to`) of the transaction. If the address matches either the sender or receiver, the
     * function returns `true`; otherwise, it returns `false`.
     */
    bool involvesAddress(const string& address) const;
};

#endif // TRANSACTION_H