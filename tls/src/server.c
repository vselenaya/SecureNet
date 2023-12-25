#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "common.h"

#define SERVER_ADDR INADDR_ANY  // адрес сетевого интерфейса, который слушает сервер
#define SERVER_PORT 4433  // порт, на котором работает сервер
#define CERT_FILE "server_cert.pem"  // файлы с сертификатом и с закрытым ключом (которым сертификат подписан) сервера
#define PRIKEY_FILE "server_private.key"



// Функция для обработки запросов клиента (соединение с которым через сокет ssl)
void servlet(SSL* ssl, int echo) {  // ssl - это как обычный сокет, только в обертке tls
                                    // echo=1, если сервер должен просто повторять то, что ему отправил клиент и 0 иначе
    char buf[BUFFER_LEN];;
    size_t bytes;

    if (SSL_accept(ssl) != 1)  // проверяем, что приняли соединение
        handleErrors("TLS-соединение не установлено!\n");

    printf("Соединение с %s криптографией...\n", SSL_get_cipher(ssl));
    printf("\n=== TLS соединение успешно установлено ===\n\n");
    printf("...ждём сообщений от клиента...\n\n");

    int dialog = 1;
    while (dialog) {
        bytes = recive_ssl(ssl, buf, BUFFER_LEN);  // получаем сообщение от клиента
        if (bytes == 0) {
            printf("Клиент завершил диалог.\n");
            break;
        }

        printf("Cообщение от клиента:\n");
        write(1, buf, bytes);
        printf("\n");

        if (echo == 1) {
            send_ssl(ssl, buf, bytes);
            continue;
        }

        printf("Введите сообщение клиенту (EXIT - выход)...\n");
        bytes = read(0, buf, BUFFER_LEN) - 1;  // bytes - количество считанных байт из stdin (-1 для без перевода строки)
        if (bytes == strlen("EXIT") && memcmp(buf, "EXIT", strlen("EXIT")) == 0) {
            dialog = 0;  // если ввели EXIT, то заканчиваем диалог
            SSL_shutdown(ssl);
            continue;
        }
        send_ssl(ssl, buf, bytes);
        printf("---> сообщение клиенту отправлено\n\n");
    }

    int sd;
    sd = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sd);
    return;
}


int main(int argc, char** argv) {
    int echo = 0;
    if (argc > 1 && strcmp(argv[1], "test_speed") == 0) {
        printf("Запуск в режиме тестирование скорости\n(вывод всех дальнейших функций отключён)\n");
        close(1);  // выключаем stdout -> убираем весь вывод всех функций!
        open("/dev/null", O_WRONLY);
        echo = 1;  // сервер используем как эхо (для проверки скорости обмена сообщениями, достаточно, чтобы сервер просто отсылал копии принятых)
    } else if (argc == 1)
        printf("ЗАПУСК СЕРВЕРА\n=============\n");
    else
        handleErrors("Некорректные параметры запуска!");


    // инициализируем то, что нужно для ssl:
    SSL_CTX *ctx;
    SSL_library_init();
    ctx = init_ctx(1);  // контекст сервера
    load_certs(ctx, CERT_FILE, PRIKEY_FILE);  // загружаем сертификат сервера
    printf("Контексты и сертификаты сервера для работы ssl загружены...\n");


    // открываем сокет сервера:
    int server;
    server = server_tcp_listener(SERVER_ADDR, SERVER_PORT);
    printf("Серверный сокет открыт...\n");
    

    int cnt = TEST_ITERS + 1;  // количество подключений, которое будет в случае тестирования скорости:
                               // TEST_ITERS раз будет создана сессия и ещё 1 раз будет создана сессия для измерения скорости обмена сообщениями

    // === основной цикл, в котором сервер ждет подключения: ===
    while (1) {  
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        printf("\nЖдём клиентов...\n");
        int client = accept(server, (struct sockaddr*)&addr, &len);  // принимаем подключение от клиента -> для него
                                                                     // создаётся отдельный tcp-сокет client - как обычно в сервере 
        printf("Принято соединение от клиента: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        SSL *ssl;
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);  // поверх клиентского сокета открываем tls-соединение

        servlet(ssl, echo);  // вызов функции для обработки запросов клиента (запуск в режиме НЕ echo)
        cnt -= 1;

        if (cnt == 0 && echo == 1)  // если был режим тестирования скорости, то только нужное количество раз запускаем
            break;
    }
    // =======


    // закрываем сокет и контекст:
    close(server);
    SSL_CTX_free(ctx);
}