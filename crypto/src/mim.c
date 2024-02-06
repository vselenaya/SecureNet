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
#include <signal.h>

#include "keypair.h"
#include "common.h"
#include "aes.h"
#include "kex.h"
#include "secure_and_net.h"



/*
Данная программа реализует атаку Man-in-the-middle.
Изначально есть настоящий клент и сервер, которые хотят общаться между собой.
Но данной приложение MIM встаёт между клиентом и сервером, а именно MIM выступает в роли сервера
для настоящего клиента и в роли клиента для настоящего сервера (то есть MIM и клиент, и сервер). После
чего настоящий клиент отправляет MIM сообщения (думая, что общается с сервером), а MIM может их перправить
настоящему серверу или изменить...

В простом случае MIM просто работает как прокси: он просто перепарвлет сообщения от клиента к серверу 
(такой MIM легко может быть в реальности и стоять на маршрутизаторе или ещё где-то - он может читать все
сообщения, но не знает что в них), но не может их дешифровать, так как клиент и сервер настроили
защищенное соединение между собой. Видоизменять сообщения тоже не очень имеет смысл, так как проверка
имитовставки HMAC не сработает... Такой MIM не мешает клиенту и серверу и не портит их коммуникацию... 

Гораздо страшнее для клиента и сервера, если MIM каким-то образом устанавливает защищенное соединени отедльно
с клиентом (тот в это время думает, что устанавливает соединение с сервером) и отдельно с сервером (такое
может быть, если клиент и сервер невнимательно поставили подтверждение открытых ключей). Вот тогда все
сообщения между клиентом и севрером MIM сможет расшифровать, видоизменить. ЧТобы такого не
произошло, нужно внимательно сравнивать открытые ключи.Ы
*/




// ============ DEFINE В РАМКАХ ДАННОГО ПРИЛОЖЕНИЯ, МОЖНО РЕДАКТИРОВАТЬ ============

#define TRUE_SERVER_ADDR "localhost"  // адрес настоящего сервера
#define TRUE_SERVER_PORT 8081
//#define MIM_SERVER_ADDR "localhost"  // адрес, где будет работать приложение MIM (в качестве сервера)
#define MIM_SERVER_PORT 9091
#define LISTEN_ADDR INADDR_ANY  // адреса сетевых устройств, которые будет слушать сервер (INADDR_ANY - все)

#define PUBKEY_FILE "mim_pubkey.pem"  // файла с ключами
#define PRIKEY_FILE "mim_prikey.pem"
#define PRIKEY_PASSWD "password"  // пароль, которым зашифрован приватный ключ

#define NAME "MIM"  // имя приложеня MIM
#define NONE_DATA (-239)  // флаг, обозначающий, что пока данные не считаны
#define TIMEOUT 1  // таймаут в секундах

static pthread_t tid;  // название потока




// ============ ОСНОВНЫЕ ФУНКЦИИ ============

// Функция, которая будет вызываться при вызове сигнала
static void alarm_handler(int signo) {
    (void) signo;
    printf("=== таймаут ===\n");
    pthread_cancel(tid);   // завершаем поток tid
}


// Эта функция, которая объединяет все аргументы в одну память с указателем void*, чтобы
// потом эту память подать на вход функции thread_recieve - то есть тут создаётся аргумент функции thread_recieve:
static void* create_args(int socket, unsigned char *buffer, size_t len) {
    char* args = (char*) malloc(sizeof(int) + sizeof(unsigned char *) + sizeof(size_t) + sizeof(int));  // создаём память
    *((int*) args) = socket;  // сначала записываем сокет
    *((unsigned char **) (args + sizeof(int))) = buffer;  // затем адрес буфера
    *((size_t*) (args + sizeof(int) + sizeof(unsigned char *))) = len;  // потом длину, которую читать
    *((int*) (args + sizeof(int) + sizeof(unsigned char *) + sizeof(size_t))) = NONE_DATA;   // в хвосте будет лежать результат -
                            // - количество считанных байт... изначально (пока ничего не считывали) кладём флаг NONE_DATA
    return args;
}


// Эта функция, которая из единой памяти (которая на вход thread_recieve) подаётся, достаёт ответ
static int get_ans(void* args) {
    int ans = *((int*) ((char*) args + sizeof(int) + sizeof(unsigned char *) + sizeof(size_t)));
    return ans;
}


// Эта функция, которая будет работать в отдельном потоке и считывать данные из сокета
// (так как в C функция для запуска в потоке должна иметь конкретную сигнатуру void* func(void*),
// то передача параметров тут довольно непростая: приходится все данные для функции  вроде сокета, буфера и тд
// записывать в одну память с указателем params... и ответ тоже через эту память получаем)
static void* thread_recive(void* params) {
    // из памяти params достаём все аргументы функции:
    char* args = (char*) params;  // превращаем в указатель на char, чтобы арифметика указателей работала
                                  // (при прибавлении числа к char* указатель сдвигается на это же чило байт
                                  // (если считать, что размер char равен 1 байт - но это верно почти везде))
    int socket = *((int*) args);  // первые байты превращаем в int - это сокет, из которого читать
    unsigned char *buffer = *((unsigned char **) (args + sizeof(int)));  // далее лежит 8 байт указателя на память bufer, куда читать
    size_t len = *((size_t*) (args + sizeof(int) + sizeof(unsigned char *)));  // и потом лежит число, сколько максимум читать

    int bytes = recive(socket, buffer, len);  // далее просто читаем данные
    *((int*) (args + sizeof(int) + sizeof(unsigned char *) + sizeof(size_t))) = bytes;  // обратно в ту же память params записываем результат

    pthread_exit(NULL);  // завершаем поток
}


// Функция для того, чтобы просто перехватывать сообщения между настоящим клиентом и 
// настоящим сервером (без дешифрования) и выводить их на экран:
void capture_data(int true_client, int true_server) {
    unsigned char get_from[BUFFER_LEN];  // буферы: сообщение, которое получено и сообщение, которое отправится
    unsigned char to_send[BUFFER_LEN];

    signal(SIGALRM, alarm_handler);  // при поступлении сигнала SIGALARM будет вызываться функция alarm_handler

    // аргументы для считывания даных от клиента, потом от сервера:
    void* args_client = create_args(true_client, get_from, BUFFER_LEN);
    void* args_server = create_args(true_server, get_from, BUFFER_LEN);

    int bytes, ans;
    int who_send = 1;  // переменная, в которой храним, от кого считали данные: 1 - client, 0 - server

    // в этом цикле поочереди пытаемся считать данные от клиента или от сервера (ждём не более таймаута):
    while(1) {
        pthread_create(&tid, NULL, thread_recive, args_client);  // в потоке tid запускаем функцию для чтения данных от клиента
        alarm(TIMEOUT);  //  ставим таймаут (если время таймаута истечёт, он досрочно прервёт поток и функция завершится)
        pthread_join(tid, NULL); // ждём, пока поток завершится 
        alarm(0);  // выключает таймер

        bytes = get_ans(args_client);  // получаем результат чтени данных
        if (bytes != NONE_DATA) {  // если что-то считали, выходим из цикла
            who_send = 1;
            break;
        }

        // если же от клиента ничего не читали, то аналогично пытаемся от сервера
        pthread_create(&tid, NULL, thread_recive, args_server);
        alarm(TIMEOUT);
        pthread_join(tid, NULL); // Wait for thread finish
        alarm(0);

        bytes = get_ans(args_server);

        if (bytes != NONE_DATA) {
            who_send = 0;
            break;
        }
    }

    free(args_client);
    free(args_server);


    // === итак, на данный момент мы считали bytes данных то ли от клиента (who_send=1), то ли от сервера (who_send=0) ===

    // проверяем, считано ли что-то
    if (bytes < 0)
        handleErrors("Ошибка получения данных");
    else if (bytes == 0) {  // результат 0 значит, что клиент или сервер послали shutdown, то есть больше не будут передавать данные
        shutdown (true_client, SHUT_WR);
        shutdown (true_server, SHUT_WR);
        printf("Клиент больше не передаёт данные\n");
        exit(0);
    }
    
    // если считаны данные, выводим, что собирается послать:
    if (who_send == 1)
        hex_dump("КЛИЕНТ собирается послать данные", get_from, bytes);
    else
        hex_dump("СЕРВЕР собирается послать данные", get_from, bytes);
    
    // проверяем, стоит ли это отправлять
    printf("Введите 1, если разрешить пересылку и 0, если хотите изменить сообщение:\n");    
    scanf("%d", &ans);
    printf("(распознан ответ: %d)\n", ans);

    if (ans == 1) {
        memcpy(to_send, get_from, bytes);
    } else {
        printf("Введите новое сообщение (ctrl+D для ввода: не enter, так как перевод строки тоже учитывается):\n");
        bytes = read(0, to_send, BUFFER_LEN);  
    }

    if (who_send == 1) {
        send_socket(to_send, bytes, true_server);
        printf("---> Сообщение от клиент серверу отправлено!\n\n");
    } else {
        send_socket(to_send, bytes, true_client);
        printf("---> Сообщение от сервера клиенту отправлено!\n\n");
    }
}


// Функция, которая перехватывает сообщение, дешифрует, выводит на экран:
void capture_and_decrypt(int true_client, int true_server, SESSION *client, SESSION *server) {
    SESSION* session[2] = {client, server};
    int socket[2] = {true_client, true_server};

    // так как тут (в отличие от предыдущей функции) мы знаем, что сообщения от клиента к серверу идут строго
    // по очереди (сначала клиент, потом сервер пишет), то нам не нужно усложнять код потоками и тд... - просто
    // читаем сначала от клиента, потом от сервера
    // (в предыдущей функции мы точно порядок не знали, так как помимо обычного обмена сообщениями, которые идут
    // по порядку и которые мы тут перехватываем, предыдущая функция также перехватывала процесс настройки
    // защищённого соединения, а там сообщения могут идти несколько раз подряд от одного из клиента или сервера...
    // поэтому в предыдущей функции было усложнение потоками, чтобы по очереди пытаться получить данные)
    for (int who_send = 0; who_send < 2; who_send += 1) {
        unsigned char message[BUFFER_LEN];
        unsigned char to_send[BUFFER_LEN];
        ssize_t len_message, len_to_send;
        crypto_get(session[who_send], socket[who_send], message, &len_message, 0);  // читаем сообщение и дешифруем

        if (who_send == 0)
            printf("КЛИЕНТ пытается отправить серверу сообщение:\n");
        else
            printf("СЕРВЕР пытается отправить серверу сообщение:\n");
        write(1, message, len_message);  // выводим на экран сообщение (1 - дискриптор файла вывода)

        int ans;
        printf("Введите 1, если разрешить пересылку и 0, если хотите изменить сообщение:\n");    
        scanf("%d", &ans);
        printf("(распознан ответ: %d)\n", ans);

        if (ans == 1) {  // модифицируем сообщение
            memcpy(to_send, message, len_message);
            len_to_send = len_message;
        } else {
            printf("Введите новое сообщение:\n");
            len_to_send = read(0, to_send, BUFFER_LEN);
        }

        if (who_send == 0)
            printf("--> СЕРВЕРУ отправлено сообщение\n");
        else
            printf("--> КЛИЕНТУ отправлено сообщение\n");
        crypto_send(session[(who_send + 1) % 2], socket[(who_send + 1) % 2], to_send, len_to_send, 0);  // отправляем сообщение
    }
}




// ============ ФУНКЦИЯ MAIN, В КОТОРОЙ ВСЕ ЗАПУСКАЕТСЯ ============

int main(int argc, char** argv) {
    // === проверка параметров запусков ===
    if ((argc != 2 && argc != 3) || (argc == 2 && strcmp(argv[1], "mim") == 0)) {
        printf("Некорректное количество аргументов!\n");
        printf("Запуск имеет вид [proxy или mim] [new_key или old_key если mim]\n");
        return 1;
    }

    int mode = 1;  // mode = 1 - режим прокси, mode = 2
    if (strcmp(argv[1], "proxy") == 0)
        mode = 1;
    else if (strcmp(argv[1], "mim") == 0)
        mode = 2;
    else {
        printf("Некорректный первый аргумент!");
        return 1;
    }



    // === инициализируем сокеты -1, чтобы знать, если их не переопределили ===
    int true_client = -1;  // сокет для общения с настоящим клиентом
    int true_server = -1;  // для настоящего сервера
    int mim_socket = -1;  // сокет MIM как сервера


    // === создаём сокет для общения с настоящим сервером ===
    struct hostent *server_info = gethostbyname(TRUE_SERVER_ADDR);
    if (!server_info) {
        perror("DNS Resolve error");
        exit(1);
    }
    
    char server_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, server_info->h_addr, server_ip, sizeof(server_ip));
    printf("Connecting to: %s\n", server_ip);
    
    true_server = socket(AF_INET, SOCK_STREAM, 0);
    if (true_server == -1) {
        perror("Socket create");
        exit(1);
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TRUE_SERVER_PORT);
    server_addr.sin_addr = *((struct in_addr *)server_info->h_addr);

    if (connect(true_server, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {  // подключаемся к серверу
        perror("Connect error");
        exit(1);
    }
    

    // === создаём сокет для общения с клиентом ===
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    mim_socket = socket(AF_INET, SOCK_STREAM, 0);  // создаём сокет приложения MIM как сервера
    if (mim_socket == -1) 
    {
        perror("Socket create");
        exit(EXIT_FAILURE);
    }

    int option = 1;
    setsockopt(mim_socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
    //struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = LISTEN_ADDR;
    server_addr.sin_port = htons(MIM_SERVER_PORT);

    if (bind(mim_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Socket bind");
        exit(EXIT_FAILURE);
    }

    if (listen(mim_socket, 1) < 0) {
        perror("Socket listen");
        exit(EXIT_FAILURE);
    }

    true_client = accept(mim_socket, (struct sockaddr *)&client_addr, &client_len);  // принимаем соединение от клиента и создаём tcp-сокет для общения
    printf("Подключен клиент!\n");

    // === далее идёт обработка общения между клиентом и сервером ===

    if (mode == 1) {
        while (1) {  // тут просто перехватываем сообщения от клиента и сервера без дешифровки (делаем в цикле, пока функция не завершит программу)
            capture_data(true_client, true_server);
        }
    
    } else {
        SESSION session_client;
        SESSION session_server;
        session_client.session_start = 0;
        session_server.session_start = 0;


        // устанавливаем глобавльные параметры и генерируем ключи
        set_globals(PUBKEY_FILE, PRIKEY_FILE, PRIKEY_PASSWD, NAME);
        if (strcmp(argv[2], "new_key") == 0) {
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

        // устанавлиаем защищённые соединения с клиентом и с сервером:
        printf("\n\n========= УСТАНОВКА СОЕДИНЕНИЯ С КЛИЕНТОМ =========\n\n\n");
        create_session(&session_client, true_client, 1);
        session_client.session_start = 1;
        printf("\n\n\n========= УСТАНОВКА СОЕДИНЕНИЯ С СЕРВЕРОМ =========\n\n\n");
        create_session(&session_server, true_server, 1);
        session_server.session_start = 1;

        printf("\n\n\n========= СОЕДИНЕНИЯ УСТАНОВЛЕНЫ =========\n\n\n");
        while(1) {  // после установки соединения перхватываем и дешифруем диалоги:
            capture_and_decrypt(true_client, true_server, &session_client, &session_server);
        }
    }
    return 0;
}