#include <stdio.h>
#include <stdlib.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>

#include "common.h"


// Функция обработки ошибок:
void handleErrors(const char *info) {
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "Дополнительная информация: %s\n", info);
    fprintf(stderr, "==========================\n");
    exit(1);  // после выхода операционная система автоматически освободит всю память, так что можно при ошибке спокойно завершать программу
}


// Функция отправки сообщения длины len из памяти buffer, сокет для общения - ssl (это сокет с TLS-соединением)
void send_ssl(SSL* ssl, void* buffer, size_t len) {
    if (len > BUFFER_LEN)
        handleErrors("Попытка отправить больше байт, чем размер буфера!");

    if (SSL_write(ssl, &len, sizeof(size_t)) != sizeof(size_t))  // сначала передаём 8 байт типа size_t - размер сообщения
        handleErrors("Размер сообщения отправить не удалось!");

    if (SSL_write(ssl, buffer, len) <= 0)  // а потом само сообщение
        handleErrors("Сообщение не отправлено!");
}


// Функция чтения сообщение длины <= bytes в response, сокет - client_socket
int recive_ssl(SSL* ssl, void* response, size_t bytes) {
    size_t len;
    int res;
    res = SSL_read(ssl, &len, sizeof(size_t));  // сначала читаем 8 байт - размер сообщения
    if (res == 0)
        return 0;  // диалог завершен
    else if (res != (int) sizeof(size_t))
        handleErrors("Некорректный формат сообщения: нет размера сообщения в начале");

    if (bytes < len) {
        printf("!!! собираетесь считать %ld данных вместо %ld доступных !!!\n", bytes, len);
        len = bytes;
    }

    if (SSL_read(ssl, response, len) != (int) len)  // теперь читаем само сообщение
        handleErrors("Некорректный формат сообщения: размер сообщения некорректен");
        
    return len;  // возвращаем количество считанных байт
}


// Функция создания клиентского сокета
int client_tcp_connect(const char *hostname, int port) {   
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL) {
        perror(hostname);
        exit(EXIT_FAILURE);
    }
    
    sd = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    
    if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {  // поключаемся к серверу
        close(sd);
        perror(hostname);
        exit(EXIT_FAILURE);
    }
    
    return sd;
}


// Функция открытия обычного tcp-сокета сервера
int server_tcp_listener(unsigned int SERVER_ADDR, int SERVER_PORT) {
    int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);  // открываем TCP-сокет
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    addr.sin_addr.s_addr = SERVER_ADDR;
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {  // подключаемся
        perror("Bind error");
        exit(EXIT_FAILURE);
    }
    if (listen(sd, CONN_MAX) != 0) {  // начинаем ждать входящих соединений
        perror("Listen error");
        exit(EXIT_FAILURE);
    }
    return sd;
}


// Функция контекста для ssl - она однократно создается пеерд всеми подключениями
SSL_CTX* init_ctx(int flag) {  // flag=1, если сервер и 0 - клиент
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();  // подгружаем алгоритмы....
    SSL_load_error_strings();
    
    if (flag == 1)
        method = TLS_server_method();  // метод выбираем - это TLS для сервера
    else
        method = TLS_client_method();  // это метод клиента

    ctx = SSL_CTX_new(method);  // контекст-обёртка для данного метода
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}


// Функция для отображения сертификата сервера по установленнуму соединению ssl
void show_certs(SSL* ssl) {   
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if ( cert != NULL ) {
        printf("Сертификат подключенного собеседника\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("Нет сертификата!\n");
}


// Функция загрузки сертификата сервера (то, что будет подсовываться клиенту)
void load_certs(SSL_CTX* ctx, char* CERT_FILE, char* PRIKEY_FILE) {
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {  // используем файл сертификата
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, PRIKEY_FILE, SSL_FILETYPE_PEM) <= 0) {  // используем файл приватного ключа
        ERR_print_errors_fp(stderr);                                             // (приватный ключ, которым сервер всё подписывает)
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Приватный ключ не соответсвтует сертификату!\n");
        exit(EXIT_FAILURE);
    }
}