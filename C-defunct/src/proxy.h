#ifndef PROXY_H
#define PROXY_H

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>


// Accept callback
void accept_callback(struct evconnlistener *listener, evutil_socket_t fd,
                     struct sockaddr *addr, int socklen, void *ctx);

// Client read and event callbacks
void client_read_cb(struct bufferevent *client_bev, void *ctx);
void client_event_cb(struct bufferevent *client_bev, short events, void *ctx);

// Relay read and event callbacks
void relay_read_cb(struct bufferevent *bev, void *ctx);
void relay_event_cb(struct bufferevent *bev, short events, void *ctx);

// HTTPS and HTTP handlers
void handle_https_connect(struct bufferevent *client_bev, char *request, size_t len, void *ctx);
void handle_http_request(struct bufferevent *client_bev, char *request, size_t len);

// Utility function
char *remove_proxy_connection_header(const char *request);

#endif // PROXY_H
