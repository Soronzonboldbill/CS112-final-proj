#ifndef SSL_UTILS_H
#define SSL_UTILS_H

#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>

typedef struct 
{
    char *contents;
    const char *filename;
    int len;
} *File;

typedef struct 
{
    File html;
    File style;
    File js;

    int is_html_copied;
    int is_style_copied;
    int is_js_copied;
} *HTML_Components;

typedef struct 
{
    X509 *ca_cert;
    EVP_PKEY *ca_key;
    FILE *output; 
    FILE *error; 
    FILE *html;
    HTML_Components html_comp;
} *Proxy_Utils; 


// Generates a certificate for a given domain
X509 *generate_certificate(const char *hostname, EVP_PKEY *ca_key, X509 *ca_cert, EVP_PKEY **out_pkey);

// Creates an SSL context for a client connection (proxy to server)
SSL_CTX *create_client_ssl_ctx();

// Creates an SSL context for a server connection with a generated certificate (proxy to client)
SSL_CTX *create_server_ssl_ctx(X509 *cert, EVP_PKEY *pkey);

#endif // SSL_UTILS_H
