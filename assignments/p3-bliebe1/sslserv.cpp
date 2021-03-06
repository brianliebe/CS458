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
#include <fstream>

using namespace std;

#define FAIL    -1

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
void LoadCertificates(SSL_CTX* ctx, string CertFile, string KeyFile)
{
	/* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile.c_str(), SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile.c_str(), SSL_FILETYPE_PEM) <= 0 )
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
    else
    {
        ShowCerts(ssl);								/* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf));	/* get request */
        if ( bytes > 0 )
        {
            buf[bytes] = 0;
            // printf("Client sent: \"%s\"\n", buf);
            string user = "";
            string pass = "";
            string hashed;
            bool after = false;
            for (int i = 0; i < bytes; i++) {
                if (buf[i] == ';') after = true;
                else if (!after) user += buf[i];
                else pass += buf[i];
            }
            hashed = sha1(pass);
            cout << "User ID: " << user << endl;
            cout << "Password: " << pass << endl;
            cout << "Hashed Password: " << hashed << endl;

            ifstream pass_file("password");
            string f_user, f_pass, f_date;
            while (pass_file >> f_user >> f_pass >> f_date) {
                if (f_user == user) {
                    if (f_pass == hashed) passwords_match = true;
                    break;
                }
            }
            if (passwords_match) HTMLecho = "OK";
            else HTMLecho = "BAD";

            sprintf(reply, HTMLecho, buf);
            SSL_write(ssl, reply, strlen(reply));
        }
        else
            ERR_print_errors_fp(stderr);
    }
    sd = SSL_get_fd(ssl);							/* get socket connection */
    SSL_free(ssl);									/* release SSL state */
    close(sd);										/* close connection */
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
        socklen_t len = sizeof(addr);
        SSL *ssl;

        int client = accept(server, (struct sockaddr *)&addr, &len);
        printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
        Servlet(ssl);
    }
    close(server);
    SSL_CTX_free(ctx);
}