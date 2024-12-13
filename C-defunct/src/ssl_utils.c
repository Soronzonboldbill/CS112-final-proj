#include "ssl_utils.h"
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>


// Generate a certificate for the given hostname
X509 *generate_certificate(const char *hostname, EVP_PKEY *ca_key, X509 *ca_cert, EVP_PKEY **out_pkey) {
    X509 *cert = X509_new();
    if (!cert) {
        fprintf(stderr, "Error creating new X509 object\n");
        return NULL;
    }

    // Generate key pair
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    // Set certificate details
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), (long)time(NULL));
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L); // 1 year

    X509_set_pubkey(cert, pkey);

    // Set subject name
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"SecureProxyCA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)hostname, -1, -1, 0);

    // Set issuer name from CA cert
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

    // Add extensions
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ca_cert, cert, NULL, NULL, 0);

    // Add basic constraints
    X509_add_ext(cert, X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:FALSE"), -1);

    // Add subject alt name
    char san[256];
    snprintf(san, sizeof(san), "DNS:%s", hostname);
    X509_add_ext(cert, X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, san), -1);

    // Add key usage
    X509_add_ext(cert, X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, 
        "critical,digitalSignature,keyEncipherment"), -1);

    // Add extended key usage
    X509_add_ext(cert, X509V3_EXT_conf_nid(NULL, &ctx, NID_ext_key_usage, 
        "serverAuth,clientAuth"), -1);

    // Sign the certificate
    X509_sign(cert, ca_key, EVP_sha256());

    *out_pkey = pkey;
    return cert;
}

// Create SSL context for connecting to the server (proxy to server)
SSL_CTX *create_client_ssl_ctx() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "Error creating SSL client context\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Load default system certificate paths
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        fprintf(stderr, "Error loading system certificate paths\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Set minimum and maximum protocol versions
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) || 
        !SSL_CTX_set_max_proto_version(ctx, 0)) { // Latest supported version
        fprintf(stderr, "Error setting TLS protocol versions\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Enable certificate verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    return ctx;
}

// Create SSL context for the client connection with generated certificate (proxy to client)
SSL_CTX *create_server_ssl_ctx(X509 *cert, EVP_PKEY *pkey) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        fprintf(stderr, "Error creating SSL server context\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Set the certificate and private key
    if (SSL_CTX_use_certificate(ctx, cert) <= 0) {
        fprintf(stderr, "Error setting certificate\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
        fprintf(stderr, "Error setting private key\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Verify that the private key matches the certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Set minimum protocol version
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        fprintf(stderr, "Error setting minimum protocol version\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}
