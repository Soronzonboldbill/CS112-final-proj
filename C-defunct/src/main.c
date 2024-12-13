#include <event2/event.h>
#include <event2/listener.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "proxy.h"
#include "ssl_utils.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>
#include <sys/stat.h>

#define HTML_PATH "../html/html.txt"
#define STYLE_PATH "../html/style.txt"
#define JS_PATH "../html/js.txt"

#define STDOUT_FILE_POS 1
#define STDERR_FILE_POS 2
#define MAX_ARGS 4

// Signal handler for clean shutdown
void signal_cb(evutil_socket_t sig, short events, void *user_data)
{
    struct event_base *base = (struct event_base *)user_data;
    printf("\nCaught signal %d, exiting...\n", sig);
    event_base_loopexit(base, NULL);
}

// Open file in read mode - for certificate files
FILE *open_cert_file(const char *filename)
{
    FILE *fp = fopen(filename, "r");
    if (fp == NULL)
    {
        fprintf(stderr, "Error opening certificate file: %s\n", filename);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return fp;
}

// Open file in write mode - for log files
FILE *open_or_abort(const char *filename)
{
    FILE *fp = fopen(filename, "w");
    if (fp == NULL)
    {
        fprintf(stderr, "Error opening log file: %s\n", filename);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    // Set line buffering for logs
    setvbuf(fp, NULL, _IOLBF, 0);
    return fp;
}

long file_size(const char *file_name)
{
    if (file_name == NULL)
    {
       return -1;
    }

    struct stat stats;
    if (stat(file_name, &stats) == 0)
    {
        return stats.st_size;
    }

    return -1;
}

File open_read_file(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) 
    {
        fprintf(stderr, "Error opening log file: %s\n", filename);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    } 

    File file = malloc(sizeof(*file)); 
    file->filename = filename;
    file->len = file_size(filename);
    file->contents = malloc(file->len);
    
    int ch, pos = 0;
    while ((ch = fgetc(fp)) != EOF) {
        file->contents[pos++] = ch; 
    }

    return file;
}

Proxy_Utils load_proxy_certs()
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    EVP_PKEY *ca_key = NULL;
    X509 *ca_cert = NULL;

    FILE *ca_cert_file = open_cert_file("../certificates/rootCA.pem");
    ca_cert = PEM_read_X509(ca_cert_file, NULL, NULL, NULL);
    fclose(ca_cert_file);

    FILE *ca_key_file = open_cert_file("../certificates/rootCA-key.pem");
    ca_key = PEM_read_PrivateKey(ca_key_file, NULL, NULL, NULL);
    fclose(ca_key_file);

    if (!ca_cert || !ca_key)
    {
        fprintf(stderr, "Error loading CA certificate or key\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    Proxy_Utils proxy_utils = malloc(sizeof(*proxy_utils));
    proxy_utils->ca_cert = ca_cert;
    proxy_utils->ca_key = ca_key;

    return proxy_utils;
}

HTML_Components make_components() {
    

    HTML_Components comp = malloc(sizeof(*comp));
    
    File html = open_read_file(HTML_PATH);
    File style = open_read_file(STYLE_PATH);
    File js = open_read_file(JS_PATH);

    comp->html = html;
    comp->style = style;
    comp->js = js;

    comp->is_html_copied = 0;
    comp->is_style_copied = 0;
    comp->is_js_copied = 0;

    return comp;
}

int main(int argc, char **argv)
{
    // Enable libevent debug mode (optional)
    // event_enable_debug_mode();

    if (argc != MAX_ARGS)
    {
        fprintf(stderr, "usage: ./proxy [stdout file] [stderr file]\n");
        return EXIT_FAILURE;
    }

    FILE *stdout_file = open_or_abort(argv[STDOUT_FILE_POS]); 
    FILE *stderr_file = open_or_abort(argv[STDERR_FILE_POS]); 
    FILE *html_file = open_or_abort(argv[3]);

    struct event_base *base;
    struct evconnlistener *listener;
    struct sockaddr_in sin;

    // Ignore SIGPIPE to prevent crashes on client disconnect
    signal(SIGPIPE, SIG_IGN);

    Proxy_Utils proxy_utils = load_proxy_certs();
    proxy_utils->output = stdout_file; 
    proxy_utils->error = stderr_file; 
    proxy_utils->html = html_file; 
    proxy_utils->html_comp = make_components(); 

    // Create the event base
    base = event_base_new();
    if (!base)
    {
        fprintf(stderr, "Could not initialize libevent. Is libevent installed correctly?\n");
        return 1;
    }

    // Handle SIGINT (Ctrl+C) for clean shutdown
    struct event *signal_event = evsignal_new(base, SIGINT, signal_cb, base);
    if (!signal_event || event_add(signal_event, NULL) < 0)
    {
        fprintf(stderr, "Could not create signal event.\n");
        return 1;
    }

    // Configure the listening address
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(8080);

    // Create a listener for incoming client connections
    listener = evconnlistener_new_bind(
        base,
        accept_callback,
        proxy_utils,
        LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
        -1,
        (struct sockaddr *)&sin, sizeof(sin));

    if (!listener)
    {
        perror("Could not create listener on port 8080. Is the port in use?");
        return 1;
    }

    printf("Proxy server running on port 8080...\n");

    // Start the event loop
    event_base_dispatch(base);

    // Clean up
    evconnlistener_free(listener);
    event_free(signal_event);
    event_base_free(base);

    X509_free(proxy_utils->ca_cert);
    EVP_PKEY_free(proxy_utils->ca_key);
    fclose(proxy_utils->output); 
    fclose(proxy_utils->error); 
    free(proxy_utils); 

    // Clean up OpenSSL
    EVP_cleanup();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();

    return 0;
}
