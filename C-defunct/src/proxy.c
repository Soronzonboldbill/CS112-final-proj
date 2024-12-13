#include "proxy.h"
#include "ssl_utils.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/stat.h>
#include <event2/bufferevent_ssl.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#define EXACT_MATCH 0
#define MAX_NUM_CHARS 10


// Define the relay_ctx struct
struct relay_ctx {
    struct bufferevent *partner_bev;
    int is_server_to_client;
    // logging files
    FILE *output;
    FILE *error;
    FILE *html;
    // Response tracking
    char *buffer;
    size_t buffer_size;
    size_t buffer_used;
    int headers_complete;
    size_t content_length;
    int is_chunked;
    int in_chunk;
    size_t chunk_remaining;
    int is_content_len_updated;
    // html components - UI only
    HTML_Components comps;
};

// Helper function to check if we have complete headers
static char *find_header_end(const char *buffer, size_t len) {
    const char *end = buffer + len - 3;  // Need at least 4 chars for "\r\n\r\n"
    const char *p;
    
    for (p = buffer; p <= end; p++) {
        if (p[0] == '\r' && p[1] == '\n' && p[2] == '\r' && p[3] == '\n') {
            return (char *)(p + 4);
        }
    }
    return NULL;
}

// Helper function to ensure buffer capacity
static int ensure_buffer_capacity(struct relay_ctx *ctx, size_t additional) {
    if (ctx->buffer_used + additional > ctx->buffer_size) {
        size_t new_size = ctx->buffer_size * 2;
        if (new_size < ctx->buffer_used + additional) {
            new_size = ctx->buffer_used + additional;
        }
        char *new_buffer = realloc(ctx->buffer, new_size);
        if (!new_buffer) return -1;
        
        ctx->buffer = new_buffer;
        ctx->buffer_size = new_size;
    }
    return 0;
}

// Helper function to parse headers
static void parse_headers(struct relay_ctx *ctx) {
    if (!ctx->buffer || !ctx->headers_complete) return;

    char *headers_end = find_header_end(ctx->buffer, ctx->buffer_used);
    if (!headers_end) return;

    // Convert headers to lowercase for case-insensitive search
    char *headers_copy = strdup(ctx->buffer);
    char *p = headers_copy;
    while (*p) {
        *p = tolower(*p);
        p++;
    }

    // Check for chunked encoding
    if (strstr(headers_copy, "transfer-encoding: chunked")) {
        ctx->is_chunked = 1;
        ctx->content_length = 0;
    } else {
        // Look for content-length
        char *content_len = strstr(headers_copy, "content-length:");
        if (content_len) { 
            fprintf(stderr, "\n\n\n==================FOUND HEADER - CONTENT LENGTH UDPATE==================\n\n\n");

            ctx->content_length = atol(content_len + 15);  // Skip "content-length:"

            size_t updated_len = ctx->content_length + ctx->comps->style->len;
            fprintf(stderr, "Old Content Length: %zu, New Content Length: %zu\n", ctx->content_length, updated_len);

            ctx->content_length += ctx->comps->style->len;

            char *content_len_start = strcasestr(ctx->buffer, "Content-Length: ");
            if (!content_len_start) {
                fprintf(stderr, "failed to find the content-length tag within the buffer\n"); 
                return;
            }

            content_len_start += strlen("Content-Length: ");

            // have to convert the number into a string to update the header - buffer len is determined by the 
            // max number possible in 32 bits (i.e. 4,294,967,296)
            char content_len_char_buffer[MAX_NUM_CHARS] = {0};
            int num_chars_content_len = sprintf(content_len_char_buffer, "%zu", updated_len); 

            char *content_len_end = content_len_start;
            while (*content_len_end != '\r' && *content_len_end != '\n') {
                content_len_end++;
            }
        
            size_t prefix_position = (content_len_start) - ctx->buffer;
            size_t suffix_position = (ctx->buffer_used - (content_len_end - ctx->buffer));
 
            fprintf(stderr, "What is the first char: %c\n", content_len_start[2]);
            fprintf(stderr, "what is the prefix pos: %zu\n", prefix_position);
            fprintf(stderr, "what is the suffix pos: %zu\n", suffix_position);

            if (ensure_buffer_capacity(ctx, num_chars_content_len) < 0)
            {
                fprintf(stderr, "could not allocate additional memory for updated content len\n");
                return;
            }

            char *new_buffer = malloc(prefix_position + num_chars_content_len + suffix_position);
            if (!new_buffer) {
                fprintf(stderr, "could not malloc updated buffer\n");
                return;
            }

            memcpy(new_buffer, ctx->buffer, prefix_position);
            memcpy(new_buffer + prefix_position, content_len_char_buffer, num_chars_content_len);
            memcpy(new_buffer + prefix_position + num_chars_content_len, content_len_end, suffix_position);

            free(ctx->buffer);
            ctx->buffer = new_buffer;
            ctx->buffer_used += num_chars_content_len; 
        }
    }

    free(headers_copy);
}

long get_file_size(char *file_name)
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

// Portable strcasestr implementation
char *strcasestr_portable(const char *haystack, const char *needle)
{
    if (!haystack || !needle)
        return NULL;

    size_t needle_len = strlen(needle);
    if (needle_len == 0)
        return (char *)haystack;

    for (; *haystack; haystack++)
    {
        if (strncasecmp(haystack, needle, needle_len) == 0)
            return (char *)haystack;
    }
    return NULL;
} 

// Function to remove 'Proxy-Connection' header
char *remove_proxy_connection_header(const char *request)
{
    char *modified_request = strdup(request);
    if (!modified_request)
    {
        return NULL;
    }
    char *proxy_conn = strcasestr_portable(modified_request, "Proxy-Connection:");
    if (proxy_conn)
    {
        char *end_of_line = strstr(proxy_conn, "\r\n");
        if (end_of_line)
        {
            end_of_line += 2; // Move past "\r\n"
            memmove(proxy_conn, end_of_line, strlen(end_of_line) + 1);
        }
        else
        {
            *proxy_conn = '\0'; // Truncate at the header if no end found
        }
    }
    return modified_request;
}

// Helper function to add or modify headers
char *modify_request_headers(const char *request) {
    // First copy the request
    char *modified = strdup(request);
    if (!modified) return NULL;

    // Remove Accept-Encoding header if present
    char *accept_encoding = strcasestr(modified, "\r\nAccept-Encoding:");
    if (accept_encoding) {
        char *end_of_line = strstr(accept_encoding + 2, "\r\n");
        if (end_of_line) {
            memmove(accept_encoding + 2, end_of_line + 2, strlen(end_of_line + 2) + 1);
        }
    }

    // Add our own Accept-Encoding header to force uncompressed content
    // First, find the end of headers (double \r\n)
    char *end_of_headers = strstr(modified, "\r\n\r\n");
    if (end_of_headers) {
        // Calculate needed space
        size_t current_len = strlen(modified);
        size_t needed_space = current_len + strlen("\r\nAccept-Encoding: identity\r\n");
        
        // Reallocate to make room
        char *new_buffer = realloc(modified, needed_space + 1);
        if (!new_buffer) {
            free(modified);
            return NULL;
        }
        modified = new_buffer;
        
        // Move the end of headers forward
        memmove(end_of_headers + strlen("\r\nAccept-Encoding: identity"),
                end_of_headers,
                strlen(end_of_headers) + 1);
                
        // Insert our header
        memcpy(end_of_headers, "\r\nAccept-Encoding: identity", 
               strlen("\r\nAccept-Encoding: identity"));
    }

    return modified;
}

char *remove_encoding(char *header)
{
  if (!header) {
    return NULL;
  }
  
  char *modified_header = strdup(header);
  char *accept_encoding = strcasestr(modified_header, "\r\nAccept-Encoding:");
  if (accept_encoding) {
      char *end_of_line = strstr(accept_encoding + 2, "\r\n");
      if (end_of_line) {
          memmove(accept_encoding + 2, end_of_line + 2, strlen(end_of_line + 2) + 1);
      }
  }

  return modified_header;
}

// Relay read callback
void relay_read_cb(struct bufferevent *bev, void *ctx) {
    struct relay_ctx *relay_ctx = (struct relay_ctx *)ctx;
    struct bufferevent *partner_bev = relay_ctx->partner_bev;
    struct evbuffer *src = bufferevent_get_input(bev);
    struct evbuffer *dst = bufferevent_get_output(partner_bev);
    
    size_t len = evbuffer_get_length(src);
    if (len == 0) return;

    // For client to server data
    if (!relay_ctx->is_server_to_client) {
        char *data = malloc(len + 1);
        if (data) {
            evbuffer_remove(src, data, len);
            data[len] = '\0';

            if (strstr(data, "HTTP/1.") && strstr(data, "POST")) {
              fprintf(stderr, "%s\n", data);
              return;
            }
            
            // Only modify if it's an HTTP request (not already in SSL tunnel)
            if (strstr(data, "HTTP/1.") && !strstr(data, "CONNECT")) {
                // char *modified = modify_request_headers(data);

                char *modified = remove_encoding(data);

                if (modified) {
                    bufferevent_write(partner_bev, modified, strlen(modified));
                    free(modified);
                    free(data);
                    return;
                }
            }
            
            // If no modification was needed or possible, forward original
            bufferevent_write(partner_bev, data, len);
            free(data);
        } else {
            evbuffer_add_buffer(dst, src);  // Fallback if malloc fails
        }
        return;
    }

    // Ensure buffer capacity
    if (ensure_buffer_capacity(relay_ctx, len) < 0) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return;
    }

    // Read data into our buffer
    evbuffer_remove(src, relay_ctx->buffer + relay_ctx->buffer_used, len);
    relay_ctx->buffer_used += len;
    relay_ctx->buffer[relay_ctx->buffer_used] = '\0';

    fprintf(stderr, "Added %zu bytes to buffer, total now %zu\n", 
            len, relay_ctx->buffer_used);

    // If headers aren't complete yet, try to parse them
    if (!relay_ctx->headers_complete) {
        char *body_start = find_header_end(relay_ctx->buffer, relay_ctx->buffer_used);
        if (body_start) {
            relay_ctx->headers_complete = 1;

            fprintf(stderr, "what is the pointer value of relay_ctx: %p\n", (void *)relay_ctx);
            parse_headers(relay_ctx);
            fprintf(stderr, "Headers complete. Chunked=%d, Content-Length=%zu\n",
                    relay_ctx->is_chunked, relay_ctx->content_length);
        } else {
            fprintf(stderr, "Still waiting for complete headers\n");
        }
    }

    // Check if we have a complete response
    int response_complete = 0;
    if (relay_ctx->headers_complete) {
        if (relay_ctx->is_chunked) {
            // Look for end of chunked response
            if (strstr(relay_ctx->buffer, "\r\n0\r\n\r\n")) {
                response_complete = 1;
                fprintf(stderr, "Found end of chunked response\n");
            } else {
                fprintf(stderr, "Waiting for end of chunked response\n");
            }
        } else if (relay_ctx->content_length > 0) {
            // Check if we have all the content
            char *body_start = find_header_end(relay_ctx->buffer, relay_ctx->buffer_used);

            if (body_start) {
                size_t body_length = relay_ctx->buffer_used - (body_start - relay_ctx->buffer);
                fprintf(stderr, "Body length so far: %zu/%zu\n", 
                        body_length, relay_ctx->content_length);
                if (body_length >= relay_ctx->content_length) {
                    response_complete = 1;
                    fprintf(stderr, "Received complete fixed-length response\n");
                }
            }
        }
    }

    // If we have a complete response, log it
    if (response_complete) {
        
        fprintf(stderr, "Logging complete response of %zu bytes\n", relay_ctx->buffer_used);
        fprintf(relay_ctx->output, "\n=== Complete HTTPS Response ===\n");
        fprintf(relay_ctx->output, "Length: %zu bytes\n", relay_ctx->buffer_used);
        fprintf(relay_ctx->output, "Content:\n%s\n", relay_ctx->buffer);  
        fprintf(relay_ctx->output, "===========================\n\n");
        fflush(relay_ctx->output);  // Force flush the output 

        if (strcasestr(relay_ctx->buffer, "Content-Length: "))
        {
            fprintf(stderr, "\n\n\nFOUND THE CONTENT LENGTH HEADER WITHIN THE RESPONSE COMPLETE BLOCK\n\n\n");
        }
         
        // Reset buffer
        relay_ctx->buffer_used = 0;
        relay_ctx->headers_complete = 0;
        relay_ctx->content_length = 0;
        relay_ctx->is_chunked = 0;
    }


    if (!relay_ctx->comps->is_style_copied && strstr(relay_ctx->buffer, "<head>")) {
    
        fprintf(stderr, "\n\n\n===========found the head tag - updated===========\n\n\n");
 
        // have to append 4 because head_start points to ['<', 'h', 'e', 'a', 'd', '>', ....]
        char *head_start = strstr(relay_ctx->buffer, "<head>") + strlen("<head>");
        size_t prefix_pos = head_start - relay_ctx->buffer;
        int style_len = relay_ctx->comps->style->len; 

        if (style_len == -1) {
            fprintf(stderr, "the style length is 0 - something went wrong, investigate the file\n");
        } 
        else {  
            if (ensure_buffer_capacity(relay_ctx, style_len) < 0) {
                fprintf(stderr, "Failed to allocate buffer - style insert\n");
                return;
            }
                      
            fprintf(stderr, "What is starting position: %zu\n", prefix_pos);
            fprintf(stderr, "What is buffer_used: %zu\n", relay_ctx->buffer_used);

            if (prefix_pos > 0 && prefix_pos + style_len < relay_ctx->buffer_size)
            {

                char *style_contents = relay_ctx->comps->style->contents;
                char *new_buffer = malloc(style_len + relay_ctx->buffer_used);
                fprintf(stderr, "COPYING THE STYLE FILE INTO THE HTML PAYLOAD\n");

                char *old_buffer = relay_ctx->buffer;
                memcpy(new_buffer, relay_ctx->buffer, prefix_pos);
                memcpy(new_buffer + prefix_pos, style_contents, style_len);
                memcpy(new_buffer + prefix_pos + style_len, relay_ctx->buffer + prefix_pos, relay_ctx->buffer_used - prefix_pos); 

                relay_ctx->buffer_used += style_len;
                // relay_ctx->buffer_size += style_len;
                relay_ctx->buffer = new_buffer;

                free(old_buffer);
                // free(style_contents);

            }
        }

        relay_ctx->comps->is_style_copied = 1; 
    }

     
    // Forward the data to the partner
    bufferevent_write(partner_bev, relay_ctx->buffer + (relay_ctx->buffer_used - len), len);
}

// Create and initialize a new relay context
struct relay_ctx *create_relay_ctx(struct bufferevent *partner, int is_server_to_client, 
                                 FILE *output, FILE *error, FILE *html, HTML_Components comps) {
    struct relay_ctx *ctx = malloc(sizeof(struct relay_ctx));
    if (!ctx) return NULL;

    ctx->partner_bev = partner;
    ctx->is_server_to_client = is_server_to_client;
    ctx->output = output;
    ctx->html = html;
    ctx->error = error;
    ctx->comps = comps;
    
    // Initialize buffer with reasonable initial size
    ctx->buffer_size = 16384;  // Start with 16KB
    ctx->buffer = malloc(ctx->buffer_size);
    if (!ctx->buffer) {
        free(ctx);
        return NULL;
    }
    
    ctx->buffer_used = 0;
    ctx->headers_complete = 0;
    ctx->content_length = 0;
    ctx->is_chunked = 0;
    ctx->in_chunk = 0;
    ctx->chunk_remaining = 0;
    ctx->is_content_len_updated = 0;

    return ctx;
}

// Clean up relay context
void free_relay_ctx(struct relay_ctx *ctx) {
    if (ctx) {
        if (ctx->buffer) {
            free(ctx->buffer);
        }
        free(ctx);
    }
}

// Event callback for handling connection events
void relay_event_cb(struct bufferevent *bev, short events, void *ctx) {
    struct relay_ctx *relay_ctx = (struct relay_ctx *)ctx;
    struct bufferevent *partner_bev = relay_ctx->partner_bev;

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        // Log any remaining data
        if (relay_ctx->is_server_to_client && relay_ctx->buffer_used > 0) {
            fprintf(relay_ctx->output, "\n=== Final Response Fragment ===\n");
            fprintf(relay_ctx->output, "Length: %zu bytes\n", relay_ctx->buffer_used);
            fprintf(relay_ctx->output, "Content:\n%s\n", relay_ctx->buffer);
            fprintf(relay_ctx->output, "===========================\n\n");


            fprintf(relay_ctx->html, "%s", relay_ctx->buffer);
        }

        if (events & BEV_EVENT_ERROR) {
            unsigned long err;
            while ((err = bufferevent_get_openssl_error(bev))) {
                char buf[256];
                ERR_error_string_n(err, buf, sizeof(buf));
                fprintf(stderr, "SSL error: %s\n", buf);
            }
        }

        bufferevent_free(bev);
        free_relay_ctx(relay_ctx);

        if (partner_bev) {
            bufferevent_data_cb readcb, writecb;
            bufferevent_event_cb eventcb;
            void *partner_ctx_ptr = NULL;
            bufferevent_getcb(partner_bev, &readcb, &writecb, &eventcb, &partner_ctx_ptr);
            struct relay_ctx *partner_ctx = (struct relay_ctx *)partner_ctx_ptr;

            bufferevent_free(partner_bev);
            if (partner_ctx) {
                free_relay_ctx(partner_ctx);
            }
        }
    }
}


// Client event callback
void client_event_cb(struct bufferevent *client_bev, short events, void *ctx)
{
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR))
    {
        if (events & BEV_EVENT_ERROR)
        {
            int err = EVUTIL_SOCKET_ERROR();
            fprintf(stderr, "Client socket error: %s\n", evutil_socket_error_to_string(err));
        }
        bufferevent_free(client_bev);
    }
}

// Handle HTTPS CONNECT method
void handle_https_connect(struct bufferevent *client_bev, char *request, size_t len, void *ctx) {
    Proxy_Utils proxy_utils = ctx;
    X509 *ca_cert = proxy_utils->ca_cert;
    EVP_PKEY *ca_key = proxy_utils->ca_key;

    // Extract host and port
    char host[256];
    int port;
    int ret = sscanf(request, "CONNECT %255[^:]:%d", host, &port);
    if (ret != 2) {
        fprintf(stderr, "Invalid CONNECT request format\n");
        bufferevent_free(client_bev);
        return;
    }
    printf("Host: %s, Port: %d\n", host, port);

    // Send "HTTP/1.1 200 Connection Established" to the client
    const char *response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    bufferevent_write(client_bev, response, strlen(response));

    // Clear the client's input buffer
    evbuffer_drain(bufferevent_get_input(client_bev), len);

    // Create SSL contexts
    SSL_CTX *server_ssl_ctx = create_client_ssl_ctx();
    if (!server_ssl_ctx) {
        bufferevent_free(client_bev);
        return;
    }

    // Generate certificate and key for the host
    EVP_PKEY *cert_pkey = NULL;
    X509 *cert = generate_certificate(host, ca_key, ca_cert, &cert_pkey);
    if (!cert || !cert_pkey) {
        bufferevent_free(client_bev);
        SSL_CTX_free(server_ssl_ctx);
        if (cert) X509_free(cert);
        if (cert_pkey) EVP_PKEY_free(cert_pkey);
        return;
    }

    // Create SSL context for the client connection
    SSL_CTX *client_ssl_ctx = create_server_ssl_ctx(cert, cert_pkey);
    if (!client_ssl_ctx) {
        bufferevent_free(client_bev);
        SSL_CTX_free(server_ssl_ctx);
        X509_free(cert);
        EVP_PKEY_free(cert_pkey);
        return;
    }

    // Create SSL objects
    SSL *client_ssl = SSL_new(client_ssl_ctx);
    SSL *server_ssl = SSL_new(server_ssl_ctx);

    // Set the SNI hostname
    if (!SSL_set_tlsext_host_name(server_ssl, host)) {
        fprintf(stderr, "Error setting SNI hostname\n");
        ERR_print_errors_fp(proxy_utils->error);
        SSL_free(server_ssl);
        SSL_free(client_ssl);
        SSL_CTX_free(client_ssl_ctx);
        SSL_CTX_free(server_ssl_ctx);
        X509_free(cert);
        EVP_PKEY_free(cert_pkey);
        return;
    }

    // Create SSL bufferevents
    struct bufferevent *client_ssl_bev = bufferevent_openssl_filter_new(
        bufferevent_get_base(client_bev),
        client_bev,
        client_ssl,
        BUFFEREVENT_SSL_ACCEPTING,
        BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

    struct bufferevent *server_bev = bufferevent_openssl_socket_new(
        bufferevent_get_base(client_bev),
        -1,
        server_ssl,
        BUFFEREVENT_SSL_CONNECTING,
        BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

    if (!client_ssl_bev || !server_bev) {
        fprintf(stderr, "Error creating SSL bufferevents\n");
        if (client_ssl_bev) bufferevent_free(client_ssl_bev);
        if (server_bev) bufferevent_free(server_bev);
        SSL_CTX_free(client_ssl_ctx);
        SSL_CTX_free(server_ssl_ctx);
        X509_free(cert);
        EVP_PKEY_free(cert_pkey);
        return;
    }

    // Create relay contexts
    struct relay_ctx *client_to_server_ctx = create_relay_ctx(server_bev, 0, 
                                                            proxy_utils->output, 
                                                            proxy_utils->error,
                                                            proxy_utils->html,
                                                            proxy_utils->html_comp);
    struct relay_ctx *server_to_client_ctx = create_relay_ctx(client_ssl_bev, 1, 
                                                            proxy_utils->output, 
                                                            proxy_utils->error,
                                                            proxy_utils->html,
                                                            proxy_utils->html_comp);

    if (!client_to_server_ctx || !server_to_client_ctx) {
        fprintf(stderr, "Failed to create relay contexts\n");
        if (client_to_server_ctx) free_relay_ctx(client_to_server_ctx);
        if (server_to_client_ctx) free_relay_ctx(server_to_client_ctx);
        bufferevent_free(client_ssl_bev);
        bufferevent_free(server_bev);
        SSL_CTX_free(client_ssl_ctx);
        SSL_CTX_free(server_ssl_ctx);
        X509_free(cert);
        EVP_PKEY_free(cert_pkey);
        return;
    }

    // Set callbacks
    bufferevent_setcb(client_ssl_bev, relay_read_cb, NULL, relay_event_cb, client_to_server_ctx);
    bufferevent_setcb(server_bev, relay_read_cb, NULL, relay_event_cb, server_to_client_ctx);

    bufferevent_enable(client_ssl_bev, EV_READ | EV_WRITE);
    bufferevent_enable(server_bev, EV_READ | EV_WRITE);

    // Connect to the target server
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int gai_ret = getaddrinfo(host, port_str, &hints, &res);
    if (gai_ret != 0) {
        fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(gai_ret));
        bufferevent_free(client_ssl_bev);
        bufferevent_free(server_bev);
        SSL_CTX_free(client_ssl_ctx);
        SSL_CTX_free(server_ssl_ctx);
        X509_free(cert);
        EVP_PKEY_free(cert_pkey);
        free_relay_ctx(client_to_server_ctx);
        free_relay_ctx(server_to_client_ctx);
        return;
    }

    // Connect to the target server using the resolved address
    if (bufferevent_socket_connect(server_bev, res->ai_addr, res->ai_addrlen) < 0) {
        fprintf(stderr, "Error connecting to target server\n");
        bufferevent_free(client_ssl_bev);
        bufferevent_free(server_bev);
        SSL_CTX_free(client_ssl_ctx);
        SSL_CTX_free(server_ssl_ctx);
        X509_free(cert);
        EVP_PKEY_free(cert_pkey);
        free_relay_ctx(client_to_server_ctx);
        free_relay_ctx(server_to_client_ctx);
        freeaddrinfo(res);
        return;
    }

    // Clean up
    freeaddrinfo(res);
    X509_free(cert);
    EVP_PKEY_free(cert_pkey);
    SSL_CTX_free(client_ssl_ctx);
    SSL_CTX_free(server_ssl_ctx);
}

// Handle HTTP request
void handle_http_request(struct bufferevent *client_bev, char *request, size_t len)
{
    // Extract method, URL, and protocol
    char method[16], url[1024], protocol[16];
    int ret = sscanf(request, "%15s %1023s %15s", method, url, protocol);
    if (ret != 3)
    {
        fprintf(stderr, "Invalid HTTP request format\n");
        free(request);
        bufferevent_free(client_bev);
        return;
    }
    printf("Method: %s, URL: %s, Protocol: %s\n", method, url, protocol);

    // Extract host and path from URL
    char host[256], path[1024];
    ret = sscanf(url, "http://%255[^/]%1023s", host, path);
    if (ret < 1)
    {
        fprintf(stderr, "Invalid URL format\n");
        free(request);
        bufferevent_free(client_bev);
        return;
    }
    if (ret == 1)
    {
        // No path provided, use "/"
        strcpy(path, "/");
    }
    printf("Host: %s, Path: %s\n", host, path);

    // Modify the request to remove 'Proxy-Connection' header
    char *modified_request = remove_proxy_connection_header(request);
    if (!modified_request)
    {
        fprintf(stderr, "Failed to allocate memory\n");
        free(request);
        bufferevent_free(client_bev);
        return;
    }

    free(request);

    // Establish a connection to the target server
    struct bufferevent *server_bev = bufferevent_socket_new(
        bufferevent_get_base(client_bev), -1, BEV_OPT_CLOSE_ON_FREE);
    if (!server_bev)
    {
        fprintf(stderr, "Error creating bufferevent for server\n");
        free(modified_request);
        bufferevent_free(client_bev);
        return;
    }

    // Set up the relay between client and server
    bufferevent_setcb(server_bev, relay_read_cb, NULL, relay_event_cb, client_bev);
    bufferevent_enable(server_bev, EV_READ | EV_WRITE);

    bufferevent_setcb(client_bev, relay_read_cb, NULL, relay_event_cb, server_bev);
    bufferevent_enable(client_bev, EV_READ | EV_WRITE);

    // Use getaddrinfo to resolve the host
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;

    int gai_ret = getaddrinfo(host, "80", &hints, &res);
    if (gai_ret != 0)
    {
        fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(gai_ret));
        free(modified_request);
        bufferevent_free(server_bev);
        bufferevent_free(client_bev);
        return;
    }

    // Connect to the target server using the resolved address
    if (bufferevent_socket_connect(server_bev, res->ai_addr, res->ai_addrlen) < 0)
    {
        fprintf(stderr, "Error connecting to target server\n");
        free(modified_request);
        bufferevent_free(server_bev);
        bufferevent_free(client_bev);
        freeaddrinfo(res);
        return;
    }

    // Free the addrinfo structure
    freeaddrinfo(res);

    // Send the modified request to the server
    bufferevent_write(server_bev, modified_request, strlen(modified_request));

    free(modified_request);

    // Clear the client's input buffer
    evbuffer_drain(bufferevent_get_input(client_bev), len);
}

// Client read callback
void client_read_cb(struct bufferevent *client_bev, void *ctx)
{
    Proxy_Utils proxy_utils = ctx; 

    struct evbuffer *input = bufferevent_get_input(client_bev);
    size_t len = evbuffer_get_length(input);
    char *request = malloc(len + 1);
    if (!request)
    {
        fprintf(stderr, "Failed to allocate memory\n");
        bufferevent_free(client_bev);
        return;
    }
    evbuffer_copyout(input, request, len);
    request[len] = '\0';

    fprintf(proxy_utils->output, "Client request:\n%s\n", request);

    if (strncmp(request, "CONNECT", 7) == 0)
    {
        printf("Handling HTTPS CONNECT method\n");

        // Handle HTTPS request
        handle_https_connect(client_bev, request, len, ctx);
    }
    else
    {
        printf("Handling HTTP request\n");

        // Handle HTTP request
        handle_http_request(client_bev, request, len);
    }

    // Note: request is freed inside handle_http_request or handle_https_connect
}

// Accept callback
void accept_callback(struct evconnlistener *listener, evutil_socket_t fd,
                     struct sockaddr *addr, int socklen, void *ctx)
{
    printf("New connection accepted\n");

    struct event_base *base = evconnlistener_get_base(listener);
    Proxy_Utils proxy_utils = ctx;

    // Create a bufferevent for the client connection
    struct bufferevent *client_bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    if (!client_bev)
    {
        fprintf(stderr, "Error creating bufferevent for client\n");
        evutil_closesocket(fd);
        return;
    }

    printf("Client bufferevent created\n");

    // Set callbacks
    bufferevent_setcb(client_bev, client_read_cb, NULL, client_event_cb, proxy_utils);
    bufferevent_enable(client_bev, EV_READ | EV_WRITE);
}
