#include <stdio.h>
#include <stdlib.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

#define BUFFER_LEN 1024  // длина буфера = макс длина всех передаваемых по сети сообщений
#define TEST_ITERS 20  // количество итераций тестирования скорости
#define CONN_MAX 5  // ????

void handleErrors(const char *info);
void send_ssl(SSL* ssl, void* buffer, size_t len);
int recive_ssl(SSL* ssl, void* response, size_t bytes);
int client_tcp_connect(const char *hostname, int port);
int server_tcp_listener(unsigned int SERVER_ADDR, int SERVER_PORT);
SSL_CTX* init_ctx(int flag);
void show_certs(SSL* ssl);
void load_certs(SSL_CTX* ctx, char* CERT_FILE, char* PRIKEY_FILE);