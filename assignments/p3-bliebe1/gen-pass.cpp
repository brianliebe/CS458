#include <iostream>
#include <string>
#include <fstream>
#include <time.h>
#include "sha1.h"

using namespace std;

string getCurrentTime() {
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    // return data/time correctly formatted
    strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct);
    return buf;
}

int main() {
    string username, password, hashed;
    ifstream infile("password");

    cout << "User ID: ";
    cin >> username;
    cout << "Password: ";
    cin >> password;
    
    string line_id, line_hash, line_time;
    while (infile >> line_id >> line_hash >> line_time) {
        if (line_id == username) {
            cout << "The ID '" << line_id << "' already exists." << endl;
            return 0;
        }
    }
    infile.close();

    // not found in file, so generate hashed password and add to file
    hashed = sha1(password);

    ofstream outfile;
    outfile.open("password", ios_base::app);
    outfile << username << " " << hashed << " " << getCurrentTime() << endl;

    cout << "User ID/Password saved to file." << endl;
    
    outfile.close();
}