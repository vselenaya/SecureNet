#pragma once

#include <stdio.h>

#define BUFFER_LEN 1024  // размер буфера (в байтах), из которого считываются сообщения
#define MSG_LEN 128  // длина случайного сообщения для подтверждения открытого ключа

#define GUARD "!239!"  // сообщение, показывающее конец отправки очередного сообщения - то есть это разделитель, флаг между сообщениями
#define GL strlen(GUARD)

#define KEY_LEN 32  // длина ключа (которым шифруются сообщения), IV, секрета HMAC в байтах
#define IV_LEN 40
#define HMAC_SECRET_LEN 40

#define SALT "Some random salt" // общая для клиента и сервера случайная соль,
#define SALT_LEN strlen("Some random salt")  // и длина


// основная структура с данными сессии
typedef struct SESSION {
    unsigned char* client_pub_key;  // публичный ключ клиента (то есть самой программы)
    int len_client;  // его длина

    unsigned char* server_pub_key;  // публичный ключ сервера (то есть того, с кем данная программа общается)
    int len_server;

    char* server;  // имя сервера

    unsigned char* session_secret;  // общий секрет клиента и сервера, из которого вырабатывается ключ шифрования, iv, секрет HMAC
    int len;  // длина секрета

    unsigned char* key;
    unsigned char* iv;
    unsigned char* hmac_secret;
    unsigned char* ID;  // идентификатор сессии (получается как конкатенация двух случаных сообщений,
                        // которые клиент и сервре подписывают для подтверждения свох открытых ключей)
    
    size_t num_send;  // счётчики отправленных и полученных сообщений
    size_t num_get;
    int session_start;  // 1, если сессия настроена и можно отправлять шифрованные сообщения (и 0 иначе)
} SESSION;


void send_socket(void* buffer, size_t len, int client_socket);
int recive(int client_socket, void* response, size_t bytes);
void crypto_send(SESSION *session, int client_socket, unsigned char *message, int len, int output);
void crypto_get(SESSION *session, int client_socket, unsigned char *response, ssize_t *recive_bytes, int output);
void create_session(SESSION *session, int client_socket, int output);
void set_globals(char *pubkey_file, char *prikey_file, char *prikey_passwd, char *name);
void free_memory(SESSION *session);