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

#include "shared.h"

using namespace std;

#define FAIL    -1

void print_header() {
    cout << "\tMain Menu" << endl;
    cout << "Please enter a number (1-4)" << endl;
    cout << "1. Vote" << endl;
    cout << "2. My vote history" << endl;
    cout << "3. Election result" << endl;
    cout << "4. Quit" << endl;
}

/*---------------------------------------------------------------------*/
/*--- OpenConnection - create socket and connect to server.         ---*/
/*---------------------------------------------------------------------*/
int OpenConnection(const char *hostname, int port)
{   int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);

    if (connect(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}

/*---------------------------------------------------------------------*/
/*--- InitCTX - initialize the SSL engine.                          ---*/
/*---------------------------------------------------------------------*/
SSL_CTX* InitCTX(void)
{   const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();		/* Load cryptos, et.al. */
    SSL_load_error_strings();			/* Bring in and register error messages */
    method = SSLv23_client_method();		/* Create new client-method instance */
    ctx = SSL_CTX_new(method);			/* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

/*---------------------------------------------------------------------*/
/*--- ShowCerts - print out the certificates.                       ---*/
/*---------------------------------------------------------------------*/
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);	/* get the server's certificate */
    if ( cert != NULL )
    {
        // printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        // printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        // printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}

/*---------------------------------------------------------------------*/
/*--- main - create SSL context and connect                         ---*/
/*---------------------------------------------------------------------*/
int main(int count, char *strings[])
{   
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[1024];
    int bytes;
    char *hostname, *portnum;

    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
	hostname=strings[1];
	portnum=strings[2];
    SSL_library_init();

    ctx = InitCTX();
    server = OpenConnection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);						/* create new SSL connection state */
    SSL_set_fd(ssl, server);				/* attach the socket descriptor */
    if ( SSL_connect(ssl) == FAIL )			/* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {   
        const char *msg;
        bool validity = true;

        // Get the user's name and voter registration number
        string name, vnumber;
        cout << "Your Name: ";
        cin >> name;
        cout << "Voter Registration Number: ";
        cin >> vnumber;

        // Build the message we'll send to the VF
        string encrypted_message = encrypt(public_key("server"), name + "||" + vnumber) + "||" + encrypt(private_key(name), name);
        msg = encrypted_message.c_str(); 

        // Send the message to the VF
        ShowCerts(ssl);
        SSL_write(ssl, msg, strlen(msg));

        // Get the response from the server
        bytes = SSL_read(ssl, buf, sizeof(buf));
        buf[bytes] = 0;

        if (string(buf) == "0") {
            // VF rejects the user
            cout << "Invalid name or registration number." << endl;
            validity = false;
        }
        else {
            system("clear");
            cout << "Welcome, " << name << "!" << endl;
        }
        while (validity) {
            print_header(); // print menu

            // Get the command from the user
            string response, candidate;
            cout << "> ";
            cin >> response;

            system("clear");
            if (response == "1") {
                // Client wants to vote, so send it to the server to check for double-voting
                msg = response.c_str();
                ShowCerts(ssl);
                SSL_write(ssl, msg, strlen(msg));
                bytes = SSL_read(ssl, buf, sizeof(buf));
                buf[bytes] = 0;

                if (string(buf) == "0") {
                    cout << "You have already voted!" << endl;
                }
                else {
                    cout << "Please enter a number (1-2)" << endl;
                    cout << "1. Tim" << endl;
                    cout << "2. Linda" << endl;
                    cout << "> ";
                    cin >> candidate;

                    // Send the encrypted message to the server
                    candidate = encrypt(public_key("server"), candidate);
                    msg = candidate.c_str();
                    SSL_write(ssl, msg, strlen(msg));
                    system("clear");
                }
            }
            else if (response == "2") {
                // Client wants its voting history, so send it to the server and get its response
                msg = response.c_str();
                ShowCerts(ssl);
                SSL_write(ssl, msg, strlen(msg));
                bytes = SSL_read(ssl, buf, sizeof(buf));
                buf[bytes] = 0;

                // The response will either be the history entry or "you have not voted", so print it
                cout << buf << endl;
            }
            else if (response == "3") {
                // Client wants to see the result of the election
                msg = response.c_str();
                ShowCerts(ssl);
                SSL_write(ssl, msg, strlen(msg));
                bytes = SSL_read(ssl, buf, sizeof(buf));
                buf[bytes] = 0;

                if (string(buf) == "0") {
                    // Not everyone has voted yet
                    cout << "The result is not available." << endl;
                }
                else {
                    // Reponse in form <tim votes>;<linda votes>, so parse it
                    string tim_votes, linda_votes;
                    int t_votes, l_votes;
                    bool switch_cand = false;
                    for (int i = 0; i < bytes; i++) {
                        if (buf[i] == ';') switch_cand = true;
                        else if (!switch_cand) tim_votes += buf[i];
                        else linda_votes += buf[i];
                    }
                    t_votes = atoi(tim_votes.c_str());
                    l_votes = atoi(linda_votes.c_str());

                    // Print out the winner
                    if (t_votes > l_votes) cout << "Tim Wins!" << endl;
                    else cout << "Linda Wins!" << endl;
                    cout << " Tim " << t_votes << endl;
                    cout << " Linda " << l_votes << endl;
                }
            }
            else if (response == "4") {
                // Quit, but tell the server first
                msg = response.c_str();
                SSL_write(ssl, msg, strlen(msg));
                break;
            }
            else {
                cout << "Please select a valid option." << endl;
            }
        }
        SSL_free(ssl);
    }
    close(server);
    SSL_CTX_free(ctx);
}