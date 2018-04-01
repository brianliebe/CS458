#ifndef SHARED_H
#define SHARED_H

#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <iterator>
#include <algorithm>
#include <vector>
#include <functional>

using namespace std;

int n;

// Key struct
typedef struct Key {
    int key;
    int n;
} Key;

// The RSA encryption/decryption algorithm
struct cryptor : binary_function<int, int, int> {
    int operator()(int input, int key) const { 
        int result = 1;
        for (int i = 0; i < key; i++) {
            result *= input;
            result %= n;
        }
        return result;
    }
};

// Encrypt using RSA algorithm
string encrypt(Key key, string msg) {
    n = key.n;
    string coded = "";
    vector<int> encrypted;
    transform(msg.begin(), msg.end(), back_inserter(encrypted), bind2nd(cryptor(), key.key));

    // Convert ints to strings and add to string
    for (int i = 0; i < encrypted.size(); i++) {
        string num = to_string(encrypted[i]);
        if (num.length() == 1) coded += "00" + num;
        else if (num.length() == 2) coded += "0" + num;
        else coded += num;
    }
    return coded;
}

// Decrypt using RSA algorithm
string decrypt(Key key, string msg) {
    n = key.n;
    string coded = "";
    vector<int> encrypted, decrypted;

    // Convert the string back into a vector of ints
    while (msg.length()) {
        encrypted.push_back(atoi(msg.substr(0, 3).c_str()));
        msg.erase(0, 3);
    }

    std::transform(encrypted.begin(), encrypted.end(), std::back_inserter(decrypted), std::bind2nd(cryptor(), key.key));

    // Convert from ints back into chars 
    for (int i = 0; i < decrypted.size(); i++) coded += decrypted[i];

    return coded;
}

// The public keys for voters and server
Key public_key(string name) {
    Key key;
    if (name == "server") {
        key.n = 391;
        key.key = 47;
    }
    else if (name == "Alice") {
        key.n = 143;
        key.key = 7;
    }
    else if (name == "Bob") {
        key.n = 187;
        key.key = 7;
    }
    else if (name == "John") {
        key.n = 319;
        key.key = 23;
    }
    return key;
}

// The private keys for voters and server
Key private_key(string name) {
    Key key;
    if (name == "server") {
        key.n = 391;
        key.key = 15;
    }
    else if (name == "Alice") {
        key.n = 143;
        key.key = 103;
    }
    else if (name == "Bob") {
        key.n = 187;
        key.key = 183;
    }
    else if (name == "John") {
        key.n = 319;
        key.key = 207;
    }
    return key;
}

#endif