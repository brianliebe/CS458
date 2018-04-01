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
#include "sha1.h"
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
        // printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        // printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        // printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else {
        // printf("No certificates.\n");
    }
}

/*---------------------------------------------------------------------*/
/*--- Servlet - SSL servlet (contexts can be shared)                ---*/
/*---------------------------------------------------------------------*/
void Servlet(SSL* ssl)	/* Serve the connection -- threadable */
{   char buf[1024];
    char reply[1024];
    int sd, bytes;
    const char* HTMLecho; // "%s"
    bool passwords_match = false;

    if ( SSL_accept(ssl) == FAIL )					/* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else {
        ShowCerts(ssl);								/* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf));	/* get request */
        if ( bytes > 0 )
        {
            buf[bytes] = 0;
            // printf("Client sent: \"%s\"\n", buf);
            string first_half = "";
            string second_half = "";

            bool after = false;

            for (int i = 0; i < bytes; i++) {
                if (buf[i] == '|') { 
                    after = true;
                    i++;
                }
                else if (!after) first_half += buf[i];
                else second_half += buf[i];
            }

            first_half = decrypt(private_key("server"), first_half);
            string name = first_half.substr(0, first_half.find("||"));
            first_half.erase(0, first_half.find("||") + 2);
            string vnumber = first_half;
            cout << " (Name: " << name << ", VNumber: " << vnumber << ")" << endl;
            second_half = decrypt(public_key("server"), second_half);

            HTMLecho = "0";
            if (second_half == name) {
                ifstream voterinfo("voterinfo");
                string name_from_file, vnumber_from_file;
                while (voterinfo >> name_from_file >> vnumber_from_file) {
                    if (name_from_file == name && vnumber_from_file == vnumber) {
                        HTMLecho = "1";
                        break;
                    }
                }
            }
            sprintf(reply, HTMLecho, buf);
            SSL_write(ssl, reply, strlen(reply));

            // Now the user is valid, so return whatever request they want

            while (true) {
                bytes = SSL_read(ssl, buf, sizeof(buf));	/* get request */
                if (bytes > 0) {
                    buf[bytes] = 0;
                    if (string(buf) == "1") {
                        HTMLecho = "1";
                        string vnumber_from_file, date;
                        ifstream history("history");
                        while (history >> vnumber_from_file >> date) {
                            if (vnumber == vnumber_from_file) {
                                HTMLecho = "0";
                                break;
                            }
                        }
                        history.close();
                        sprintf(reply, HTMLecho, buf);
                        SSL_write(ssl, reply, strlen(reply));

                        if (HTMLecho == "1" ) {
                            bytes = SSL_read(ssl, buf, sizeof(buf));
                            if (bytes > 0) {
                                buf[bytes] = 0;
                                string vote = decrypt(private_key("server"), string(buf));
                                ifstream result_in("results");
                                string candidate;
                                int tim_votes, linda_votes;
                                result_in >> candidate >> tim_votes;
                                result_in >> candidate >> linda_votes;

                                if (vote == "1") tim_votes++;
                                else if (vote == "2") linda_votes++;
                                result_in.close();
                                ofstream result_out("results");
                                result_out << "Tim " << tim_votes << endl;
                                result_out << "Linda " << linda_votes << endl;
                                result_out.close();

                                ofstream history2;
                                history2.open("history", ios_base::app);
                                history2 << vnumber << " " << getCurrentTime() << endl;
                                history2.close();

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
                                if (everyone_voted) {
                                    ifstream result("results");
                                    int t_votes, l_votes;
                                    result >> name >> t_votes;
                                    result >> name >> l_votes;
                                    if (t_votes > l_votes) cout << "Tim Wins!" << endl;
                                    else cout << "Linda Wins!" << endl;
                                    cout << "\tTim " << t_votes << endl;
                                    cout << "\tLinda " << l_votes << endl;
                                }
                            }
                        }
                    }
                    else if (string(buf) == "2") {
                        ifstream history("history");
                        string vn, date, line;
                        HTMLecho = "0";
                        while (history >> vn >> date) {
                            if (vnumber == vn) {
                                line = vn + " " + date;
                                HTMLecho = line.c_str();
                                break;
                            }
                        }
                        sprintf(reply, HTMLecho, buf);
                        SSL_write(ssl, reply, strlen(reply));
                    }
                    else if (string(buf) == "3") {
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
                        ifstream results("results");
                        if (everyone_voted) {
                            string t_votes, l_votes;
                            results >> candidate >> t_votes;
                            results >> candidate >> l_votes;
                            string line = t_votes + ";" + l_votes;
                            HTMLecho = line.c_str();
                        }
                        else {
                            HTMLecho = "0";
                        }
                        results.close();
                        sprintf(reply, HTMLecho, buf);
                        SSL_write(ssl, reply, strlen(reply));
                    }
                    else if (string(buf) == "4") {
                        break;
                    }
                }
            }

        }
        else
            ERR_print_errors_fp(stderr);
    }
    sd = SSL_get_fd(ssl);							/* get socket connection */
    SSL_free(ssl);									/* release SSL state */
    close(sd);										/* close connection */
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

        int client = accept(server, (struct sockaddr *)&addr, &len);		/* accept connection as usual */
        cout << "Connection: " << inet_ntoa(addr.sin_addr) << ":" << ntohs(addr.sin_port);
        ssl = SSL_new(ctx);         					/* get new SSL state with context */
        SSL_set_fd(ssl, client);						/* set connection socket to SSL state */
        Servlet(ssl);									/* service connection */
    }
    close(server);										/* close server socket */
    SSL_CTX_free(ctx);									/* release context */
}