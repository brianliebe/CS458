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

typedef struct Key {
    int key;
    int n;
} Key;

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

string encrypt(Key key, string msg) {
    n = key.n;
    string coded = "";
    string nums = "";
    vector<int> encrypted;
    transform(msg.begin(), msg.end(), back_inserter(encrypted), bind2nd(cryptor(), key.key));
    for (int i = 0; i < encrypted.size(); i++) {
        string num = to_string(encrypted[i]);
        if (num.length() == 1) coded += "00" + num;
        else if (num.length() == 2) coded += "0" + num;
        else coded += num;
    }
    return coded;
}

string decrypt(Key key, string msg) {
    n = key.n;
    string coded = "";
    vector<int> encrypted, decrypted;

    while (msg.length()) {
        encrypted.push_back(atoi(msg.substr(0, 3).c_str()));
        msg.erase(0, 3);
    }

    std::transform(encrypted.begin(), encrypted.end(), std::back_inserter(decrypted), std::bind2nd(cryptor(), key.key));

    for (int i = 0; i < decrypted.size(); i++) coded += decrypted[i];

    return coded;
}

Key public_key(string name) {
    Key key;
    key.n = 391;
    key.key = 47;
    return key;
}
Key private_key(string name) {
    Key key;
    key.n = 391;
    key.key = 15;
    return key;
}

string digital_signature(string name) {
    return name;
}

#endif