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




// ============ ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ С ИНФОРМАЦИЕЙ ============

static char *PUBKEY_FILE, *PRIKEY_FILE, *PRIKEY_PASSWD;  // файлы с ключами и пароль
static char *NAME;  // уникальное имя пользователя
int __dialog__ = 1;  // 1, если диалог клиента и сервера ещё не закончился и 0 иначе 




// ============ ФУНКЦИИ СЕТЕВОГО ВЗАИМОДЕЙСТВИЯ ============

// Функция отправки сообщения длины len из памяти buffer, сокет для общения - client_socket
void send_socket(void* buffer, size_t len, int client_socket) {
    if (len > BUFFER_LEN)
        handleErrors("Попытка отправить больше байт, чем размер буфера!");

    if (send(client_socket, buffer, len, 0) < 0) {
        perror ("Server request error\n");
        exit(1);
    }
    if (send(client_socket, GUARD, GL, 0) < 0) {  // в конце отправляем знак, что сообщение кончилось
        perror ("Server request error\n");
        exit(1);
    }
}


// Функция чтения сообщение длины <= bytes в response, сокет - client_socket
int recive(int client_socket, void* response, size_t bytes) {
    char* dest = (char*) malloc(bytes + GL);  // куда считывать байты сообщения + знак окончания отправки
    char* start_dest = dest;

    size_t cnt = 0;
    while (1) {
        if (recv(client_socket, dest, 1, 0) <= 0)  // читаем по одному байту
            return -1;

        dest += 1;  // двиагем указатель на память, куда считывать
        bytes -= 1;
        cnt += 1;  // счётчик считанного

        if (cnt >= GL && memcmp(dest - GL, GUARD, GL) == 0)  // если поcледние GL байт совпали с признаком конца сообщения,
            break;  // заканчиваем             (проверяем, что вообще считали GL байт...)

        if (bytes == 0) // если байты чтения закончились, а GUARD так и не встретили, значит что-то не так в коммуникации
            handleErrors("Некорректный формат обмена сообщениями!");
    }

    int recv_bytes = dest - GL - (char*) start_dest;  // всего считали байт (без GL)
    memcpy(response, start_dest, recv_bytes); 
    free(start_dest);
    return recv_bytes;  // возвращаем количество считанных байт
}




// ============ ФУНКЦИИ, ОТВЕЧАЮЩИЕ ЗА НАСТРОЙКУ ШИФРОВАННОЙ СЕССИИ: проверка ключей, создание секрета и тд ============

// Функция создания имени файла вида:
// client_X_info_Y, где X - имя клиента (то есть данной программы), Y - сервера
// (имя записывается в info_name)
static void create_info_file(SESSION *session, char* info_name) {
    char *pref1 = "client_";  // префикс названия файла
    memcpy(info_name, pref1, strlen(pref1));
    memcpy(info_name + strlen(pref1), NAME, strlen(NAME));
    char *pref2 = "_info_";
    memcpy(info_name + strlen(pref1) + strlen(NAME), pref2, strlen(pref2));
    strcpy(info_name + strlen(pref1) + strlen(NAME) + strlen(pref2), session->server);  // добавялем имя серера к префиксу
}


// Функция для начала коммуникации:
// ! так как данный код будет запущен и в качестве клиента, и в качестве сервера, то, когда внутри 
// кода или в комментариях пишется "сервер", то имеется в виду то второе приложение, с которым ведётся общение,
// а если пишется "клиент", то имеется в виду именна эта программа (короче клиентом называем программу,
// котора работает на нашей стороне, а сервером - удаленную с нашей стороны программу... если перейти на
// удаленную сторону, то названия поменяются местами)
static void init_comm(SESSION *session, int client_socket) {
    unsigned char response[BUFFER_LEN];  // инициаровали память для приёма ответов от сервера
    ssize_t bytes_received;

    // === отправляем имя серверу: ===
    send_socket(NAME, strlen(NAME), client_socket);  // клиент отправил имя
    printf("---> Серверу отправлено имя %s\n", NAME);
    
    // === считываем и сохраняем имя сервера: ===
    if ((bytes_received = recive(client_socket, response, sizeof(response))) <= 0)
        handleErrors("Нет имени сервера в ответ");

    session->server = (char*) malloc(bytes_received+1);
    memcpy(session->server, (char*) response, bytes_received);
    session->server[bytes_received] = '\0';

    printf("Сервер прислал своё имя %s\n", session->server);

    // === отправляем публичный ключ серверу: ===
    send_socket(session->client_pub_key, session->len_client, client_socket);  // клиент отправил публичный ключ
    printf("---> Серверу отправлен публичный ключ\n");

    // === получаем и сохраняем публичный ключ сервера: ===
    if ((bytes_received = recive(client_socket, response, sizeof(response))) <= 0)
        handleErrors("Нет публичного ключа сервера");

    session->server_pub_key = (unsigned char*) malloc(bytes_received+1);
    memcpy(session->server_pub_key, response, bytes_received);
    session->server_pub_key[bytes_received] = 0;  // добавляем ноль в конец, чтобы получилась строка

    session->len_server = bytes_received;
    printf("Сервер прислал свой ключ:\n%s\n", session->server_pub_key);

    // === сохранение/подтверждение открытого ключа сервера в файл: ===
    char info_name[BUFFER_LEN];  // строка с названием info-файла, куда сохраним публичный ключ, который нам прислал сервер (позднее мы его проверим с помощью подписи)
    create_info_file(session, info_name);

    if (is_file(info_name)) {  // если файл есть, значит сервер с этим именем уже известен
        int len_curr_key;
        unsigned char *curr_key = serialize_pub_key(&len_curr_key, info_name);  // достаём сохранённый открытый ключ из файла
        if (memcmp(session->server_pub_key, curr_key, min(session->len_server, len_curr_key)) == 0 &&
            session->len_server == len_curr_key)
            printf("Сервер %s найден!\n", session->server);  // это случай, когда сохранённый открытый ключ сервера сопал с отправленным серврером до этого
        else {
            printf("Подтвердите изменение открытого ключа сервера %s: новый ключ\n%s\n(введите 1)\n", session->server, session->server_pub_key);
            int ans;
            scanf("%d", &ans);
            if (ans == 1)
                deserialize_pub_key(session->server_pub_key, session->len_server, info_name);  // здесь перезаписываем открытый ключ сервера в файл на новый
            else
                handleErrors("Нет подтверждения изменения ключа серера!");
        }
        free(curr_key);

    } else {  // если ещё не было такого сервера:
        printf("Подтвердите нового клиента %s с открытым ключом\n%s\n(введите 1)\n", session->server, session->server_pub_key);
        int ans;
        scanf("%d", &ans);
        if (ans == 1) 
            deserialize_pub_key(session->server_pub_key, session->len_server, info_name);
        else
            handleErrors("Нет подтверждения нового серера!");    
    }
    printf("\n");
}


// Функция, генерирущая имитовставку HMAC для сообщения ciphertext длины ciphertext_len
// hmac - память, куда записывать иситовставку, ptr_hmac_len - длина имитовставки
// flag = 1 - это send (то есть отправляем сообщение серверу),
//      = -1 - get (то есть получаем сообщение) - от этого зависит, какой счётчик сообщений использовать
// а    = 0 - без номера, то есть счётчик в hmac не добавляем
static void gen_HMAC(SESSION *session, unsigned char *ciphertext,
                     int ciphertext_len, unsigned char *hmac,
                     unsigned int *ptr_hmac_len, int flag) {
    // если отправляем просто сообщение (то есть flag = 0 или если sesson ещё не установлена до конца - 
    // это нужно, когда обмениваемся случанйми строчками для подтверждения открытого ключа - это
    // делается один раз, поэтому счётчик не нужен), то просто делаем HMAC из сообщения:
    if (flag == 0 || session->ID == NULL || session->session_start == 0) {
        HMAC(EVP_sha256(), session->hmac_secret, HMAC_SECRET_LEN, 
            ciphertext, ciphertext_len,
            hmac, ptr_hmac_len
            );
        
        return;
    } 
    
    // создаём память, в которую добавляем само сообщение и ID сессии: 
    unsigned char *msg = (unsigned char *) malloc(ciphertext_len + 2 * MSG_LEN + sizeof(size_t));
    memcpy(msg, ciphertext, ciphertext_len);
    memcpy(msg + ciphertext_len, session->ID, 2 * MSG_LEN);  // ID-сессии состоит из двух сообщений -> его длины = 2 * MSG_LEN

    // а еще добавялем нужный счётчик отправки или получения сообщений:
    if (flag == 1) {
        memcpy(msg + ciphertext_len + 2 * MSG_LEN, &(session->num_send), sizeof(size_t));
        session->num_send += 1;  // наращиваем счётчик
    } else if (flag == -1) {
        memcpy(msg + ciphertext_len + 2 * MSG_LEN, &(session->num_get), sizeof(size_t));
        session->num_get += 1;
    }

    // и от всего вместе считаем hmac:
    HMAC(EVP_sha256(), session->hmac_secret, HMAC_SECRET_LEN, 
        msg, ciphertext_len + 2 * MSG_LEN + sizeof(size_t),
        hmac, ptr_hmac_len
        );
    free(msg);   
}


// Функция отправки сообщения message длины len, сокет - client_socket
// (сообщение шифруется AES-256 и снабжается имитовставкой HMAC)
// output = 1 говорит, что нужно выводит информацию на экран (= 0 - ничего не выводим)
void crypto_send(SESSION *session, int client_socket, unsigned char *message, int len, int output) {
    unsigned char ciphertext[BUFFER_LEN];  // шифрованный текст, который отправим
    unsigned char plaintext[BUFFER_LEN];  // исхрдный текст
    int plaintext_len, ciphertext_len;

    if (message == NULL) {  // если сообщения нет, то его вводят с клавиатуры
        printf("Введите сообщение (EXIT - выход):\n");
        plaintext_len = read(0, plaintext, BUFFER_LEN);  // читаем с stdin
        if (plaintext_len == strlen("EXIT")+1 && memcmp(plaintext, "EXIT", strlen("EXIT")) == 0) {
            __dialog__ = 0;  // если ввели EXIT, то заканчиваем диалог
            shutdown (client_socket, SHUT_WR);
            return;
        }
    } else {  // иначе само message - нужное сообщение
        memcpy(plaintext, message, len);
        plaintext_len = len;
    }

    ciphertext_len = encrypt(plaintext, plaintext_len, session->key, session->iv, ciphertext);  // шифруем

    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len; 

    gen_HMAC(session, ciphertext, ciphertext_len, hmac, &hmac_len, 1);  // считаем имитовставку

    send_socket(ciphertext, ciphertext_len, client_socket);  // отправляем сообщение и имитовсатвку
    send_socket(hmac, hmac_len, client_socket);
    if (output == 1) {
        printf("--> Отправили шифрованное сообщение: ");
        hex_dump ("Ciphertext", ciphertext, ciphertext_len);
        hex_dump ("--> и HMAC для этого сообщения", hmac, hmac_len);
    }
}


// Функция получения ответа, его расшифровку помещаем в responce
// output = 1 говорит, что нужно выводит  нформацию на экран (= 0 - ничего не выводим)
void crypto_get(SESSION *session, int client_socket, unsigned char *response, ssize_t *recive_bytes, int output) {
    unsigned char ciphertext[BUFFER_LEN];
    unsigned char decryptedtext[BUFFER_LEN];
    int decryptedtext_len, ciphertext_len;

    if ((ciphertext_len = recive(client_socket, ciphertext, BUFFER_LEN)) <= 0)  // читаем сообщение
        handleErrors("Нет сообщения от сервера");

    unsigned char get_hmac[EVP_MAX_MD_SIZE];
    unsigned int get_hmac_len; 
    if ((get_hmac_len = recive(client_socket, get_hmac, EVP_MAX_MD_SIZE)) <= 0)  // читаем HMAC
        handleErrors("Нет HMAC сообщения от сервера");

    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len; 

    gen_HMAC(session, ciphertext, ciphertext_len, hmac, &hmac_len, -1);  // генерируем HMAC

    decryptedtext_len = decrypt(ciphertext, ciphertext_len, session->key, session->iv, decryptedtext);  // расшифровывем сообщение
    decryptedtext[decryptedtext_len] = '\0';

    if (output == 1) {
        printf("Получили шифрованное сообщение и расшифровали: ");
        printf("%s", decryptedtext);
    }

    if (get_hmac_len == hmac_len && memcmp(get_hmac, hmac, hmac_len) == 0) { // сравниваем полученный HMAC с тем, который должен быть
        if (output == 1)
            printf("HMAC корректен\n\n");
    } else {
        if (output == 1)
            printf("HMAC не подходит!\n\n");
    }
    if (response != NULL) {  // если есть куда сохранять, сохраняем (если нет, то ничего не делаем)
        memcpy(response, decryptedtext, decryptedtext_len);
        *recive_bytes = decryptedtext_len;
    }
}


// Функция обмена ключами для создания общего секрета:
static void exchange_key(SESSION *session, int client_socket) {
    EVP_PKEY *pkey1 = ecdh_pkey();  // создаются клиентские ключи
    size_t pubkey1_len;
    unsigned char *pubkey1 = pubkey_put(pkey1, &pubkey1_len);  // создаем наш (клиента) публичный ключ для общего секрета
    hex_dump("Peer pubkey (ключ данного пира для общего секрета)", pubkey1, pubkey1_len);

    send_socket(pubkey1, pubkey1_len, client_socket);
    printf("---> Открытый ключ для общего секрета отправлен\n");
    
    size_t pubkey2_len = 0;
    unsigned char *pubkey2;
    char response[BUFFER_LEN];
    ssize_t bytes_received = 0;
    
    if ((bytes_received = recive(client_socket, response, sizeof(response) - 1)) <= 0) {  // читаем ключ сервера
        handleErrors("Нет ключа для общего секрета от сервера");
    } else {
        pubkey2 = (unsigned char*) malloc(bytes_received);
        memcpy(pubkey2, response, bytes_received);
        pubkey2_len = bytes_received;
    }

    unsigned char *s1;
    size_t s1_len;

    s1 = ecdh_secret (pkey1, pubkey2, pubkey2_len, &s1_len);  // из двух ключей получаем общий секрет - он есть только у сервера и клиента, окружающие его не знают!
    hex_dump("Общий секрет", s1, s1_len);
    session->session_secret = (unsigned char*) malloc(s1_len);  // сохраняем его (для секрета выделяем память отдельным malloc, чтобы не
    memcpy(session->session_secret, s1, s1_len);  // тянуть в session указатель на память из функции ecdh_secret...
                                                  // для удобства всю память выделяем явно отдельным malloc, а потом в конце кода всё сразу free)
    session->len = s1_len;

    OPENSSL_free(s1);
    EVP_PKEY_free(pkey1);
    OPENSSL_free(pubkey1);
    free(pubkey2);
}


// Функция AES - а именно генерации из общего секрета клиента и сервера: ключа шифрования (которым
// будут шифроваться сообщения в диалоге с побощью AES-256), iv (инициализационный вектор тоже для шифрования сообщений),
// секрета для создания имитовставки - все три строки будут одинаковы для клиента и сервера (так как из общего секрета)
static void create_aes(SESSION *session) {
    EVP_KDF *kdf;  // инициализируем контекст
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[5], *p = params;  // и вектор параметров

    // выделяем память под все три строки: ключ (32 байта) + IV (16 байт) + сектрет HMAC (оставшиеся 40 байт):
    unsigned char *derived = (unsigned char *) malloc(KEY_LEN + IV_LEN + HMAC_SECRET_LEN); 
    // (можно выделить память и побольше, если нужны еще какие-то секреты... смысл в том, что из общего секрета
    // можно нагенерировать сколько угодно общих секретных данных: ключи iv, секреты hmac и так далее)


    // создаём контекст:
    if ((kdf = EVP_KDF_fetch(NULL, "hkdf", NULL)) == NULL)
        handleErrors("hkdf");
    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL)
        handleErrors("kctx");

    // заполняем вектор паарметров и заполянем контекст:
    *p++ = OSSL_PARAM_construct_utf8_string("digest", "sha256", (size_t)7);  // хэш-функция
    *p++ = OSSL_PARAM_construct_octet_string("salt", SALT, SALT_LEN);  // добавляем соль  
    *p++ = OSSL_PARAM_construct_octet_string("key", session->session_secret, session->len);  // общий секрет: SHARED_SECRET, SHARED_SECRET_LEN
    *p = OSSL_PARAM_construct_end();

    if (EVP_KDF_CTX_set_params(kctx, params) <= 0)
        handleErrors("params");

    if (EVP_KDF_derive(kctx, derived, KEY_LEN + IV_LEN + HMAC_SECRET_LEN, NULL) <= 0)  // заполянем память получеными из общего секрета байтами
        handleErrors("derive");

    // высвобождаем контекст
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);

    // получаем нужные строчки, выводим и сохраняем их:
    unsigned char *aes_key = derived + 0;
    unsigned char *aes_iv  = derived + KEY_LEN;
    unsigned char *hmac_secret  = derived + KEY_LEN + IV_LEN;

    hex_dump ("AES-256 KEY", aes_key, KEY_LEN);
    hex_dump ("AES-256 IV", aes_iv, IV_LEN);
    hex_dump ("HMAC SECRET", aes_iv, HMAC_SECRET_LEN);
    printf("\n\n");
    session->key = aes_key;
    session->iv = aes_iv;
    session->hmac_secret = hmac_secret;
}


// Функция проверки открытого ключа сервера: 
// (сервер нам (клиенту) прислал свой открытый ключ - с его помощью мы проверяем, знаем ли мы уже такой сервер или нет
// (проверяем по наличию файла client_X_info_Y), но нам нужно проверить, что присланный открытый ключ действительно
// принадлежит серверу - для этого сервер должен подтвердить, что у него есть парный закрытый ключ, которым
// он подписывает случайное сообщение, а мы его проверяем)
// (аналогично и мы серверу посылаем случайное сообщение, подписанное своим ключом, чтобы сервер проверил пуюличный ключ)
static void check_public_key(SESSION *session, int client_socket) {
    printf("Начинаем процедуру проверки подлинности открытого ключа...\n");

    // === Читаем (свой клиентский) приватный ключ из файла: ===
    EVP_PKEY *private_key = NULL;
    FILE *private_key_file = fopen(PRIKEY_FILE, "rb");
    if (private_key_file == NULL)
        handleErrors("Ошибка открытия файла приватного ключа: open rb");
    private_key = PEM_read_PrivateKey(private_key_file, NULL, NULL, PRIKEY_PASSWD);  
    fclose(private_key_file);
    if (private_key == NULL)
        handleErrors("Ошибка чтения публичного ключа: load");

    // создаём память под ID сессии (он нужен для дополнительной защиты HMAC от подделки)
    // - в качестве него используем два случайных сообщения, которыми обменяются сервер и клиент:
    session->ID = (unsigned char *) malloc(2 * MSG_LEN);

    // === Данные: ===
    unsigned char msg [MSG_LEN];  // сообщение
    size_t sig_len;  // длина подписанного (закрытым ключом) сообщения
    unsigned char *sig = NULL;  // подписанное сообщение

    if (RAND_poll() != 1)
        handleErrors("init random");
    if (RAND_bytes(msg, MSG_LEN) != 1)  // заполянем рандомными данными
        handleErrors("gen random msg");

    // === Подписываем своё (клиентское) сообщение и отправляем на сервер: ===
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); // создаём контекст для шифрования     
    if (ctx == NULL)
        handleErrors("ctx new");
    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, private_key) != 1)  // инициализируем его для электронной подписи
        handleErrors("sign init");
    if (EVP_DigestSign(ctx, NULL, &sig_len, msg, MSG_LEN) != 1)  // получаем длину подписанного сообщения
        handleErrors("sig len");
    if ((sig = OPENSSL_zalloc(sig_len)) == NULL)  // аллоцировали память под подпись
        handleErrors("sig buffer alloc");
    if (EVP_DigestSign(ctx, sig, &sig_len, msg, MSG_LEN) != 1)  // теперь длина sig_len известна -> записали память самой подписью
        handleErrors("sign");
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(private_key);

    hex_dump("---> Серверу отправлено сообщение", msg, MSG_LEN);
    hex_dump("---> и подпись", sig, sig_len);
    printf("=== шифрованный вид: ===\n");
    crypto_send(session, client_socket, msg, MSG_LEN, 1);  // отправляем сообщение
    crypto_send(session, client_socket, sig, sig_len, 1);  // отправляем подпись
    printf("========================\n\n");
    memcpy(session->ID, msg, MSG_LEN);  // перекопировали первую половину ID в память
    OPENSSL_free(sig);

    // === теперь проверяем подпись сообщения, которое получаем от сервера =====
    unsigned char response[BUFFER_LEN];
    ssize_t bytes_received;

    printf("=== попытка расшифровать сообщение от сервера (скорее всего какая-то ерунда, так как это случайное сообщение): ===\n");
    crypto_get(session, client_socket, response, &bytes_received, 1);  // считываем сообщение и расшифровываем в response
    if (bytes_received != MSG_LEN)
        handleErrors("Нет сообщения от сервера");
    memcpy(msg, response, MSG_LEN);  // сохраняем его

    crypto_get(session, client_socket, response, &bytes_received, 1);  // считывем подпись и сохраняем в response
    if (bytes_received <= 0)
        handleErrors("Нет подписи от сервера");
    printf("========================\n\n");
    sig = OPENSSL_zalloc(bytes_received);    
    memcpy(sig, response, bytes_received);  // сохраняем подпись
    sig_len = bytes_received;

    printf("Получили от сервера %s сообщение", session->server);  
    hex_dump("", msg, MSG_LEN);  // выврдим то, что получили от сервера в 16-ти ричном виде
    hex_dump(" и подпись", sig, sig_len);

    EVP_PKEY *public_key = NULL;
    char SERVER_PUBKEY_FILE[BUFFER_LEN];  // это файл, в котором в init_comm() мы сохранили публичный ключ сервера, который тот нам отправил
    create_info_file(session, SERVER_PUBKEY_FILE);
    FILE *public_key_file = fopen(SERVER_PUBKEY_FILE, "rb");  // открываем этот файл 
    if (public_key_file == NULL)
        handleErrors("Ошибка открыть info-файл с ключом сервера: open rb");
    public_key = PEM_read_PUBKEY(public_key_file, &public_key, NULL, NULL);  // и читаем из него ключ - это тот клч. который предоставил сервер - его сейчас проверим
    fclose(public_key_file);
    if (public_key == NULL)
        handleErrors("Ошибка загрузки публичного ключа из info-файла: load");

    ctx = EVP_MD_CTX_new();    
    if (ctx == NULL) 
        handleErrors("Ошибка создания контекста: ctx new");
    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, public_key) != 1)
        handleErrors("Ошибка создания контекста подписи: sign init");
    
    if (EVP_DigestVerify(ctx, sig, sig_len, msg, MSG_LEN) == 1) {  // проверяем подпись: а именно проверяем, правда ли сообщение msg было подписано сервером - то есть проверяем открытый ключ сервера 
        printf("=== Подлинность сервера %s подтверждена! === \n\n", session->server);
    } else {
        printf("!!! Сервер %s поддельный!\n", session->server);
        exit(1);
    }

    memcpy(session->ID + MSG_LEN, msg, MSG_LEN);  // докопируем вторую половину ID
    // важное замечание: так как один и тот же код используется и в клиенте, и в сервере, то в session->ID
    // эти половинки msg, которые туда мы копировали, окажутся в разном порядке, поэтому, чтобы session->ID был
    // одинаковым на обеих сторонах, мы упорядочи половинки session->ID по возрастанию:
    if (memcmp(session->ID, session->ID + MSG_LEN, MSG_LEN) < 0) {  // если половинки убывают
        unsigned char *temp = (unsigned char *) malloc(MSG_LEN);  // меняем их местами
        memcpy(temp, session->ID, MSG_LEN);
        memcpy(session->ID, session->ID + MSG_LEN, MSG_LEN);
        memcpy(session->ID + MSG_LEN, temp, MSG_LEN);
        free(temp);
    }

    // Итак, теперь ключи сервера подтверждены, идентификатор сессии получен, а значит соединение установлено
    hex_dump("Соединение установлено, идентификатор сессии", session->ID, 2 * MSG_LEN);
    printf("\n\n");
    EVP_PKEY_free(public_key);
    EVP_MD_CTX_free(ctx);
    OPENSSL_free(sig);
}




// ============ ОБЩИЕ ФУНКЦИИ ============

// Функция, где происходит установление соединения от начала и до возможности шифрованной коммуникации:
// output = 1 говорит, что нужно выводить информацию на экран (= 0 - ничего не выводим)
void create_session(SESSION *session, int client_socket, int output) {
    int old_stdout = dup(1);
    if (output == 0) { // если ничего выводить на экран не нужно, заменяем stdout (файл вывода) на /dev/null
        close(1);
        open("/dev/null", O_WRONLY);
    }

    session->client_pub_key = serialize_pub_key(&(session->len_client), PUBKEY_FILE);  // сохраняем свой публичный ключ
    init_comm(session, client_socket);
    exchange_key(session, client_socket);
    create_aes(session);
    check_public_key(session, client_socket);
    session->num_send = 0;
    session->num_get = 0;

    if (output == 0) {
        close(1);
        dup2(old_stdout, 1);  // после заменяем его обратно
        close(old_stdout);
    }
}


// Функция для передачи значений глобальным переменным:
void set_globals(char *pubkey_file, char *prikey_file, char *prikey_passwd, char *name) {
    PUBKEY_FILE = pubkey_file;
    PRIKEY_FILE = prikey_file;
    PRIKEY_PASSWD = prikey_passwd;
    NAME = name;
}


// Функция для очистки выделенной памяти:
void free_memory(SESSION *session) {
    free(session->client_pub_key);  // высвобождаем память
    free(session->server_pub_key);
    free(session->server);
    free(session->session_secret);
    free(session->key);  // удаляется память, в которой лежат key, iv, hmac_secret (на нее один указатель)
    free(session->ID);
}