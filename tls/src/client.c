#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
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


#define SERVER_ADDR "localhost"  // адрес, где находится сервер
#define SERVER_PORT 4433  // номер порта, где работает сервер
#define CERT_FILE "server_cert.pem"  // файл с самоподписанным сертификатом сервера - он известен клиенту заранее,
                                  // чтобы клиент мог взять отсюда открытый ключ сервера и провреить им
                                  // тот сертификат, что ему пришлёт сервер... в реальности сертификат сервера 
                                  // должен быть подписан центром сертификации CA, тогда тут стоит указать 
                                  // как раз сертификат этого CA (для тех же целей: чтобы клиент взял из него
                                  // открытый ключ и им проверил присалнный ему сертфиикат сервера)


// Функция полного создания соединения с сервером через TLS:
static void tls_with_server(SSL **ptr_ssl, SSL_CTX **ptr_ctx, int *ptr_client) {
    // инициализируем контекст и библиотеку:
    SSL_CTX *ctx;
    SSL_library_init();
    ctx = init_ctx(0);  // контекст клиента
    printf("Контекст клиента для работы ssl загружен...\n");


    // сокет клиента:
    int client;
    client = client_tcp_connect(SERVER_ADDR, SERVER_PORT);  // сокет для клеинта
    printf("Есть соединение с сервером...\n");


    // включаем провреку сертификата от сервера:
    if (SSL_CTX_load_verify_locations(ctx, CERT_FILE, NULL) != 1)  // передаем настоящий сертификат сервера
        handleErrors("Не удалось добавить сертификат!");               // (в реальности он должен проверяться корневым сертификатом, но тут не получилось так сделать...
                                                                       // поэтому явно передаём сертификат сервера - он, конечно, самоподписанный - то есть подлинность сертификата
                                                                       // будет проверяться по открытому ключу этого же сертификата)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);  // проверка сертификатов включена


    // открываем tls-соединение поверх сокета:
    SSL *ssl;  
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client);

    if (SSL_connect(ssl) != 1)  // проверяем, что подключение удалось (сертификат сервера прощел проверку)
        handleErrors("Сертификат не настоящий!");
    
    printf("Соединение с %s криптографией...\n\n", SSL_get_cipher(ssl));
    printf("Сертификат сервера успешно принят:\n");
    show_certs(ssl);  // выводим сертификат
    printf("\n=== TLS соединение успешно установлено ===\n\n");

    
    // сохраняем результат:
    *ptr_ssl = ssl;
    *ptr_ctx = ctx;
    *ptr_client = client;
}


// Функция для завершения tls-соединения:
void end_tls(SSL* ssl, SSL_CTX* ctx, int client) {
    SSL_shutdown(ssl);  // послыаем серверу информацию, что соединение закончено
    SSL_free(ssl);
    close(client);  // закрываем сокет
    SSL_CTX_free(ctx);
}


// Функция для вычисления по массиву x длины n среднего mean и стандартного отклонения std:
static void calc_mean_std(double x[], int n, double *mean, double *std) {
    *mean = 0;
    *std = 0;
    for (int i = 0; i < n; i ++) {
        *mean += x[i];
        *std += x[i] * x[i];
    }
    *mean /= n;  // mean(x) = (x1 + x2 + ... + xn) / n
    *std = sqrt(*std / n - *mean * *mean);  // std(x) = mean(x^2) - mean(x)^2
}


// Функция, реализующая полную проверку скорости:
static void check_speed() {
    double mean_session, std_session, mean_messages, std_messages;
    int old_stdout;

    printf("Начинаем тестирование скорости...\n");


    // === Скорость сосздания сессии... ===
    old_stdout = dup(1);  // выключаем stdout -> убираем весь вывод всех функций!
    close(1);
    open("/dev/null", O_WRONLY);

    double time_to_session[TEST_ITERS];
    for (int i = 0; i < TEST_ITERS; i ++) {
        clock_t start = clock();  // запускаем таймер
        SSL* ssl;
        SSL_CTX* ctx;
        int client;
        tls_with_server(&ssl, &ctx, &client);
        time_to_session[i] = (double)(clock() - start) / CLOCKS_PER_SEC;  // добавляем вычисленное время
        sleep(1.5);  // задержка, чтобы севрер точно успел настроить подключение
        end_tls(ssl, ctx, client);
    }
    calc_mean_std(time_to_session, TEST_ITERS, &mean_session, &std_session);

    close(1);
    dup2(old_stdout, 1);  // после включаем stdout обратно 
    close(old_stdout);

    printf("Скорость создания TLS-сессии:\n");
    printf("    средняя скорость: %f\n", mean_session);
    printf("    стандартное отклонение: %f\n", std_session);
    printf("    количество итераций: %d\n\n", TEST_ITERS);


    // === Скорость отправки сообщений... ===
    old_stdout = dup(1);  // выключаем stdout -> убираем весь вывод всех функций!
    close(1);
    open("/dev/null", O_WRONLY);

    SSL* ssl;
    SSL_CTX* ctx;
    int client;
    tls_with_server(&ssl, &ctx, &client);

    double time_exhange_meassages[TEST_ITERS];
    int bytes = 1000;
    unsigned char message[bytes];  // инициируем массив сообщения

    if (RAND_poll() != 1)
        handleErrors("init random");  // создание генератора случайных чисел

    for (int i = 0; i < TEST_ITERS; i ++) {
        if (RAND_bytes(message, bytes) != 1)  // заполянем рандомными данными
            handleErrors("gen random msg");

        clock_t start = clock();  // запускаем таймер
        send_ssl(ssl, message, bytes);
        recive_ssl(ssl, message, bytes);
        time_exhange_meassages[i] = (double)(clock() - start) / CLOCKS_PER_SEC;  // добавляем вычисленное время
    }
    calc_mean_std(time_exhange_meassages, TEST_ITERS, &mean_messages, &std_messages);

    close(1);
    dup2(old_stdout, 1);  // после включаем вывод обратно
    close(old_stdout);

    printf("Скорость обмена парой сообщений (длины %d байт):\n", bytes);
    printf("    средняя скорость: %f\n", mean_messages);
    printf("    стандартное отклонение: %f\n", std_messages);
    printf("    количество итераций: %d\n\n", TEST_ITERS);

    end_tls(ssl, ctx, client);
}


// ======== ОБЩАЯ ФУНКЦИЯ MAIN ========
int main(int argc, char** argv) {
    if (argc > 1 && strcmp(argv[1], "test_speed") == 0) {
        check_speed();
        return 0;
    }
    else if (argc == 1)
        printf("ЗАПУСК КЛИЕНТА\n=============\n");
    else
        handleErrors("Некорректные параметры!");


    SSL* ssl;
    SSL_CTX* ctx;
    int client;
    tls_with_server(&ssl, &ctx, &client);  // создаём TLS-соединение с сервером
    
    int dialog = 1;
    while(dialog) {
        char buf[BUFFER_LEN];
        size_t bytes;

        printf("Введите сообщение для сервера (EXIT - выход):\n");
        bytes = read(0, buf, BUFFER_LEN) - 1;
        if (bytes == strlen("EXIT") && memcmp(buf, "EXIT", strlen("EXIT")) == 0)
            break;

        send_ssl(ssl, buf, bytes);  // отправляем данные через TLS-протокол
        printf("--> Отправили сообщение для сервера\n\n");
        
        bytes = recive_ssl(ssl, buf, BUFFER_LEN);  // получаем данные
        if (bytes == 0) {
            printf("Сервер закончил диалог.\n");
            break;
        }
        printf("Ответ сервера:\n");
        write(1, buf, bytes);
        printf("\n");
    }
    
    end_tls(ssl, ctx, client);

    return 0;
}
