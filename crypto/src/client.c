#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>     
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <math.h>
#include <openssl/rand.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#include "keypair.h"
#include "common.h"
#include "aes.h"
#include "kex.h"
#include "secure_and_net.h"




// ============ DEFINE В РАМКАХ ДАННОГО ПРИЛОЖЕНИЯ, МОЖНО РЕДАКТИРОВАТЬ ============

/*Данное приложение будет запускаться и в качестве клиента, и в качестве сервера. Поэтому настройки сразу
для двух вариантов:*/

#define SERVER_ADDR "localhost"  // доменное имя (url-адрес) сервера, к которому подключаемся (для режима КЛИЕНТ)
#define RUN_SERVER_PORT 8081 // номер порта, на котором работает сервере (режим СЕРВЕР)
#define CONNECT_SERVER_PORT 8081  // номер порта, к которому подключаемся (режим КЛИЕНТ)
// (если мы не хотим атаку Man-in-the-middle, то RUN_ и CONNECT_ SERVER_PORT должны совпадать)

#define LISTEN_ADDR INADDR_ANY // - адрес, который слушает сервер (INADDR_ANY - все, 
                               //   inet_addr("192.168.0.1"); - если нужен конкретный) (режим СЕРВЕР)

#define TEST_ITERS 20  // количество итераций для измерения скорости




// ============ ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ С ИНФОРМАЦИЕЙ ============

static char *PUBKEY_FILE, *PRIKEY_FILE, *PRIKEY_PASSWD;  // файлы с ключами и пароль
static char *NAME;  // уникальное имя пользователя
extern int __dialog__;  // 1, если диалог клиента и сервера ещё не закончился и 0 иначе
                        // (extern показывает, что переменная опредеена в другом файле)



// ============ ФУНКЦИИ ОБЩЕГО НАЗНАЧЕНИЯ ============

// Функция для вычисления по массиву x длины n среднего mean и стандартного отклонения std:
static void calc_mean_std(double x[], int n, double *mean, double *std) {
    *mean = 0;
    *std = 0;
    for (int i = 0; i < n; i ++) {
        *mean += x[i];
        *std += x[i] * x[i];
    }
    *mean /= n;  // mean(x) = (x1 + x2 + ... + xn) / n
    *std = sqrt(*std / n - *mean * *mean);  // std(x) = sqrt(mean(x^2) - mean(x)^2)
}


// Функция, реализующая полную проверку скорости:
static void check_speed(SESSION *session, int client_socket) {
    double mean_session, std_session, mean_messages, std_messages;

    printf("Начинаем тестирование скорости...\n");

    double time_to_session[TEST_ITERS];
    for (int i = 0; i < TEST_ITERS; i ++) {
        clock_t start = clock();  // запускаем таймер
        create_session(session, client_socket, 0);  // создаём сессию (вывод на экран не делаем!)
        time_to_session[i] = (double)(clock() - start) / CLOCKS_PER_SEC;  // добавляем вычисленное время

        free_memory(session);
    }
    calc_mean_std(time_to_session, TEST_ITERS, &mean_session, &std_session);

    printf("Скорость создания сессии (защищенного соединения):\n");
    printf("    средняя скорость: %f\n", mean_session);
    printf("    стандартное отклонение: %f\n", std_session);
    printf("    количество итераций: %d\n\n", TEST_ITERS);
    
    create_session(session, client_socket, 0);  // создаём сессию для отправки сообщений


    double time_exhange_meassages[TEST_ITERS];
    int bytes = 1000;  // именно такой длины сообщения будем отправлять в рамках тестирования скорости
                       // (максимальную длину BUFFER_LEN =1024 лучше не использовать, так как шифротекст
                       // от сообщения такой длины может быть больше, чем BUFFER_LEN по длине и тогда он не отправится) 
    unsigned char message[bytes];  // инициируем массив сообщения
    unsigned char reply[bytes];
    ssize_t recive_bytes;

    if (RAND_poll() != 1)
        handleErrors("init random");
    if (RAND_bytes(message, bytes) != 1)  // заполянем рандомными данными
        handleErrors("gen random msg");

    for (int i = 0; i < TEST_ITERS; i ++) {
        clock_t start = clock();  // запускаем таймер
        crypto_send(session, client_socket, message, bytes, 0);
        crypto_get(session, client_socket, reply, &recive_bytes, 0);
        time_exhange_meassages[i] = (double)(clock() - start) / CLOCKS_PER_SEC;  // добавляем вычисленное время
    }
    calc_mean_std(time_exhange_meassages, TEST_ITERS, &mean_messages, &std_messages);

    printf("Скорость обмена парой сообщений (длины %d байт):\n", bytes);
    printf("    средняя скорость: %f\n", mean_messages);
    printf("    стандартное отклонение: %f\n", std_messages);
    printf("    количество итераций: %d\n\n", TEST_ITERS);
}




// ============ ФУНКЦИЯ MAIN, В КОТОРОЙ ВСЕ ЗАПУСКАЕТСЯ ============

int main(int argc, char** argv) {
    int client_socket = -1;  // инициализируем сокеты -1, чтобы знать, если их не переопределили
    int server_socket = -1;

    // === проверка параметров ===
    if (argc < 3 || argc > 4) {
        printf("Некорректные параметры!\n");
        printf("Запуск производится с параметрами: [server или client] [test_speed или new_key или old_key] [only_connection - опционально]\n");
        exit(1);
    }

    // === режим запуска: клиент или сервер ===
    if (strcmp(argv[1], "client") == 0) {  // случай, когда код запускается как клиент
        printf("Запуск КЛИЕНТА\n---------------\n");

        PUBKEY_FILE = "client_key_pub.pem";  // задаём имена файлов с ключами
        PRIKEY_FILE = "client_key.pem";
        PRIKEY_PASSWD = "password";
        NAME = "bbcli";  // задаём имя

        struct hostent *server_info = gethostbyname(SERVER_ADDR);  // получаем информацию о сервере по имени
        if (!server_info) {
            perror("DNS Resolve error");
            exit(1);
        }
        
        char server_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, server_info->h_addr, server_ip, sizeof(server_ip));  // из информации достаём ip сервера
        printf("Connecting to: %s\n", server_ip);
        
        client_socket = socket(AF_INET, SOCK_STREAM, 0);  // создаём сокет клиента для общения
        if (client_socket == -1) {
            perror("Socket create");
            exit(1);
        }

        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(CONNECT_SERVER_PORT);
        server_addr.sin_addr = *((struct in_addr *)server_info->h_addr);

        if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {  // подключаемся к серверу
            perror("Connect error");
            exit(1);
        }
    }
    else if (strcmp(argv[1], "server") == 0) {  // режим сервера
        printf("Запуск СЕРВЕРА\n-----------\n");

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        PUBKEY_FILE = "server_key_pub.pem";
        PRIKEY_FILE = "server_key.pem";
        PRIKEY_PASSWD = "password";
        NAME = "bbserv";

        server_socket = socket(AF_INET, SOCK_STREAM, 0);  // создаём серверный сокет
        if (server_socket == -1) 
        {
            perror("Socket create");
            exit(EXIT_FAILURE);
        }

        int option = 1;
        setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));  // специальная команда, чтобы можно
                                                                                       // было снова использовать сокет сразу
                                                                                       // после завершения программы!
        // источник: https://stackoverflow.com/questions/5106674/error-address-already-in-use-while-binding-socket-with-address-but-the-port-num
        
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = LISTEN_ADDR;
        server_addr.sin_port = htons(RUN_SERVER_PORT);

        if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("Socket bind");
            exit(EXIT_FAILURE);
        }

        if (listen(server_socket, 1) < 0) {
            perror("Socket listen");
            exit(EXIT_FAILURE);
        }

        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);  // принимаем соединение от клиента и создаём tcp-сокет для общения с подключившимся клиентом
    }
    else {
        printf("Некорректный 1-ый параметр %s!\n", argv[1]);
        exit(1);
    }

    // устанавливаем переменные внутри файла secure_and_net
    set_globals(PUBKEY_FILE, PRIKEY_FILE, PRIKEY_PASSWD, NAME);
    

    // === Далее начинается код общий для клиента и сервера ===
 
    SESSION session;  // создаём сессию для общения
    session.session_start = 0;  // пока что этап диалога не начался

    if (strcmp(argv[2], "test_speed") == 0) {
        check_speed(&session, client_socket);
        goto end;
    }
    else if (strcmp(argv[2], "new_key") == 0) {
        printf("Генерируем новую пару открытый-закрытый ключ\n\n");
        key_gen(PUBKEY_FILE, PRIKEY_FILE, PRIKEY_PASSWD);
    }
    else if (strcmp(argv[2], "old_key") == 0) {
        if (is_file(PUBKEY_FILE) == 1 && is_file(PRIKEY_FILE) == 1)
            printf("Пара открытый-закрытый ключ остаётся прежней\n\n");
        else {
            printf("Файлы с открытым-закрытым ключом не найдены... генерируем новые\n\n");
            key_gen(PUBKEY_FILE, PRIKEY_FILE, PRIKEY_PASSWD);
        }
    }
    else {
        printf("Некорректный 2-ой аргумент!\n");
        exit(1);
    }
    
    
    create_session(&session, client_socket, 1);  // создаём сессию - защищенное соединение
    session.session_start = 1;  // устаналиваем значение в 1

    if (argc == 4 && strcmp(argv[3], "only_connection") == 0) {  // если нас интересует только соединение (без обмена сообщениями)
        shutdown (client_socket, SHUT_WR);  // отсылаем на сервер информацию, что больше сообщений не будет
        goto end;
    }

    printf("==== Диалог ==== \n\n");
    __dialog__ = 1;  // устанавливаем переменную в 1

    while (1) {
        crypto_send(&session, client_socket, NULL, 0, 1);
        if (__dialog__ == 0)
            break;
        crypto_get(&session, client_socket, NULL, 0, 1);
    }

end:
    free_memory(&session);
    if (client_socket != -1)  // закрываем сокеты
        close(client_socket);
    if (server_socket != -1)
        close(server_socket);
    return 0;
}
