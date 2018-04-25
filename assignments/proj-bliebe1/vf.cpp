#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <iostream>
#include "shared.h"
#include <fstream>
#include <time.h>

using namespace std;

#define FAIL    -1

string getCurrentTime() {
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    // return data/time correctly formatted
    strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct);
    return buf;
}

/*---------------------------------------------------------------------*/
/*--- OpenListener - create server socket                           ---*/
/*---------------------------------------------------------------------*/
int OpenListener(int port)
{   int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if ( bind(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}

/*---------------------------------------------------------------------*/
/*--- InitServerCTX - initialize SSL server  and create context     ---*/
/*---------------------------------------------------------------------*/
SSL_CTX* InitServerCTX(void)
{   const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();		/* load & register all cryptos, etc. */
    SSL_load_error_strings();			/* load all error messages */
    method = SSLv23_server_method();	/* create new server-method instance */
    ctx = SSL_CTX_new(method);			/* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

/*---------------------------------------------------------------------*/
/*--- LoadCertificates - load from files.                           ---*/
/*---------------------------------------------------------------------*/
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	/* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

/*---------------------------------------------------------------------*/
/*--- ShowCerts - print out certificates.                           ---*/
/*---------------------------------------------------------------------*/
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);	/* Get certificates (if available) */
    if ( cert != NULL )
    {
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        free(line);
        X509_free(cert);
    }
    else {
        // ...
    }
}

/*---------------------------------------------------------------------*/
/*--- Servlet - SSL servlet (contexts can be shared)                ---*/
/*---------------------------------------------------------------------*/
void Servlet(SSL* ssl)	/* Serve the connection -- threadable */
{   char buf[1024];
    char reply[1024];
    int sd, bytes;
    const char* server_response;

    if ( SSL_accept(ssl) == FAIL )
        ERR_print_errors_fp(stderr);
    else {
        ShowCerts(ssl);
        // read name and vnumber from client
        bytes = SSL_read(ssl, buf, sizeof(buf));
        if (bytes > 0)
        {
            buf[bytes] = 0;
            string first_half = ""; // contains name and vnumbers
            string second_half = ""; // contains digital signature of user's name

            // split the message at the ||
            bool after = false;
            for (int i = 0; i < bytes; i++) {
                if (buf[i] == '|') { 
                    after = true;
                    i++;
                }
                else if (!after) first_half += buf[i];
                else second_half += buf[i];
            }

            // Get the name and vnumber from the first half of the message
            first_half = decrypt(private_key("server"), first_half); // decrypt using private key of server
            string name = first_half.substr(0, first_half.find("||")); // get the name
            first_half.erase(0, first_half.find("||") + 2);
            string vnumber = first_half; // get the vnumber

            // Decrypt the digital signature using the public key of the user
            second_half = decrypt(public_key(name), second_half);

            // Print user/vnumber to standard output
            cout << " (Name: " << name << ", VNumber: " << vnumber << ")" << endl;

            // Check to see if the user & vnumber are valid
            server_response = "0";
            if (second_half == name) {
                ifstream voterinfo("voterinfo");
                string name_from_file, vnumber_from_file;
                while (voterinfo >> name_from_file >> vnumber_from_file) {
                    if (name_from_file == name && vnumber_from_file == vnumber) {
                        server_response = "1";
                        break;
                    }
                }
            }

            // Reply to the client
            sprintf(reply, server_response, buf);
            SSL_write(ssl, reply, strlen(reply));

            // Now the user is valid, so return whatever request they want
            if (server_response == "1")
            while (true) {
                // Read the client's request 
                bytes = SSL_read(ssl, buf, sizeof(buf));

                if (bytes > 0) {
                    buf[bytes] = 0;
                    if (string(buf) == "1") {
                        // The client wants to vote
                        server_response = "1";
                        string vnumber_from_file, date;
                        ifstream history("history");

                        // Check history to see if they've voted before
                        while (history >> vnumber_from_file >> date) {
                            if (vnumber == vnumber_from_file) {
                                // If the have, return "0"
                                server_response = "0";
                                break;
                            }
                        }
                        history.close();

                        // Reply to the client
                        sprintf(reply, server_response, buf);
                        SSL_write(ssl, reply, strlen(reply));

                        // If they haven't voted, we need to receive their vote
                        if (server_response == "1" ) {
                            // Read the vote
                            bytes = SSL_read(ssl, buf, sizeof(buf));

                            if (bytes > 0) {
                                buf[bytes] = 0;
                                
                                // Decrypt their vote using the private key of the server
                                string vote = decrypt(private_key("server"), string(buf));

                                // Read the results file and save the info (we will overwrite it)
                                ifstream result_in("results");
                                string candidate;
                                int tim_votes, linda_votes;
                                result_in >> candidate >> tim_votes;
                                result_in >> candidate >> linda_votes;
                                result_in.close();

                                // Update the votes
                                if (vote == "1") tim_votes++;
                                else if (vote == "2") linda_votes++;

                                // Rewrite the results file with the new information
                                ofstream result_out("results");
                                result_out << "Tim " << tim_votes << endl;
                                result_out << "Linda " << linda_votes << endl;
                                result_out.close();

                                // Add a new entry to the history file
                                ofstream history2;
                                history2.open("history", ios_base::app); // append, not overwrite
                                history2 << vnumber << " " << getCurrentTime() << endl;
                                history2.close();

                                // Check to see if everyone has voted
                                ifstream voterinfo("voterinfo");
                                string name, date, vn1, vn2;
                                bool everyone_voted = true;
                                while (voterinfo >> name >> vn1) {
                                    ifstream history("history");
                                    bool found = false;
                                    while (history >> vn2 >> date) {
                                        if (vn1 == vn2) {
                                            found = true;
                                            break;
                                        }
                                    }
                                    history.close();
                                    if (!found) {
                                        everyone_voted = false;
                                        break;
                                    }
                                }
                                // If everyone has voted, print the winner and vote totals, otherwise, do nothing
                                if (everyone_voted) {
                                    ifstream result("results");
                                    int t_votes, l_votes;
                                    result >> name >> t_votes;
                                    result >> name >> l_votes;
                                    cout << "-------------" << endl;
                                    if (t_votes > l_votes) cout << "Tim Wins!" << endl;
                                    else cout << "Linda Wins!" << endl;
                                    cout << " Tim " << t_votes << endl;
                                    cout << " Linda " << l_votes << endl;
                                    cout << "-------------" << endl;
                                }
                            }
                        }
                    }
                    else if (string(buf) == "2") {
                        // Client wants to see their voting history
                        ifstream history("history");
                        string vn, date, line;
                        server_response = "You have not voted yet."; // the default response
                        while (history >> vn >> date) {
                            if (vnumber == vn) {
                                // If they have voted, send them the line in "history"
                                line = vn + " " + date;
                                server_response = line.c_str();
                                break;
                            }
                        }

                        // Send the line to the client
                        sprintf(reply, server_response, buf);
                        SSL_write(ssl, reply, strlen(reply));
                    }
                    else if (string(buf) == "3") {
                        // Client wants to see if there is a winner

                        ifstream voterinfo("voterinfo");
                        string name, date, vn1, vn2, candidate;
                        bool everyone_voted = true;
                        while (voterinfo >> name >> vn1) {
                            ifstream history("history");
                            bool found = false;
                            while (history >> vn2 >> date) {
                                if (vn1 == vn2) {
                                    found = true;
                                    break;
                                }
                            }
                            history.close();
                            if (!found) {
                                everyone_voted = false;
                                break;
                            }
                        }
                        voterinfo.close();

                        // Get the results from the file, and send them to the client as <tim votes>;<linda votes>
                        ifstream results("results");
                        if (everyone_voted) {
                            string t_votes, l_votes;
                            results >> candidate >> t_votes;
                            results >> candidate >> l_votes;
                            string line = t_votes + ";" + l_votes;
                            server_response = line.c_str();
                        }
                        else {
                            // If everyone didn't vote, we just respond with "0"
                            server_response = "0";
                        }
                        results.close();

                        // Send message to client
                        sprintf(reply, server_response, buf);
                        SSL_write(ssl, reply, strlen(reply));
                    }
                    else if (string(buf) == "4") {
                        // Client wants to disconnect, so disconnect
                        break;
                    }
                }
            }

        }
        else ERR_print_errors_fp(stderr);
    }
    sd = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sd);
    cout << "Closing connection" << endl;
}

/*---------------------------------------------------------------------*/
/*--- main - create SSL socket server.                              ---*/
/*---------------------------------------------------------------------*/
int main(int count, char *strings[])
{   SSL_CTX *ctx;
    int server;
    char *portnum;

    if ( count != 2 )
    {
        printf("Usage: %s <portnum>\n", strings[0]);
        exit(0);
    }
    portnum = strings[1];
    SSL_library_init();
    ctx = InitServerCTX();
    LoadCertificates(ctx, "cert.pem", "cert.pem");
    server = OpenListener(atoi(portnum));
    while (1)
    {   struct sockaddr_in addr;
        socklen_t len;
        len = sizeof(addr);
        SSL *ssl;

        int client = accept(server, (struct sockaddr *)&addr, &len);
        cout << "Connection: " << inet_ntoa(addr.sin_addr) << ":" << ntohs(addr.sin_port);
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        // Go to Servlet function, where the majority of the "stuff" is
        Servlet(ssl);
    }
    close(server);
    SSL_CTX_free(ctx);
}