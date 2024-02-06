#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>  // open function
#include <unistd.h>  // close function
#include <string.h>

#include "common.h"
#include "keypair.h"


// Функция получения размера файла:
static size_t get_file_size(const char* file_name){
	size_t _file_size = 0;
	struct stat _fileStatbuff;
	int fd = open(file_name, O_RDONLY);

	if (fd == -1)
		handleErrors("Файл для получения размера не открылся");
	
	else {
		if ((fstat(fd, &_fileStatbuff) != 0) || (!S_ISREG(_fileStatbuff.st_mode)))
			handleErrors("Ошибка определения размера файла");
		else
			_file_size = _fileStatbuff.st_size;
		close(fd);
	}
              
	return _file_size;
}


// Функция генерирования пары открытый-закрытый ключ и сохранения их в файлы PUBKEY_FILE и PRIKEY_FILE:
void key_gen(char* PUBKEY_FILE, char* PRIKEY_FILE, char* PRIKEY_PASSWD) {
    // === Cоздаём контекст для генерации ключей из элиптической кривой Ed25519: ===
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL); 
    if (pctx == NULL)
        handleErrors("Ошибка создания контекста Ed25519");
    if (EVP_PKEY_keygen_init(pctx) != 1) // создаём генератор ключей
        handleErrors("Ошибка создания генератора ключей");
    EVP_PKEY *pkey = NULL;  // общий тип для пары ключей
    if (EVP_PKEY_keygen(pctx, &pkey) != 1)  // генерируем открытый и закрытый ключ
        handleErrors("Ошибка генерации ключей");
    EVP_PKEY_CTX_free(pctx);  // освобождаем контекст


    // === Записываем публичный ключ в файл: ===
    FILE *public_key_file = fopen(PUBKEY_FILE, "wb");
    if (public_key_file == NULL)
        handleErrors("PUBKEY_FILE wb open");
    if (PEM_write_PUBKEY(public_key_file, pkey) != 1)
        handleErrors(" PUBKEY_FILE write");
    if (fclose(public_key_file) == EOF)
        handleErrors(" PUBKEY_FILE close");


    // === Записываем приватный ключ в файл: ===
    FILE *private_key_file = fopen(PRIKEY_FILE, "wb");
    if (private_key_file == NULL)
        handleErrors(" PUBKEY_FILE wb open");
    if (PEM_write_PKCS8PrivateKey(private_key_file, pkey,
                                  EVP_aes_256_cbc(), NULL,
                                  0, NULL, PRIKEY_PASSWD) <= 0) // сохраняем приватный ключ в шифрованном виде (шифруем паролем PRIKEY_PASSWD)
        handleErrors(" PUBKEY_FILE write");
    if (fclose(private_key_file) == EOF)
        handleErrors(" PRIKEY_FILE close");
    EVP_PKEY_free(pkey);  // Освобождаем ключи

    return;
}


// Функция сериализации публичного ключа - просто из файла его читаем как строку:
unsigned char* serialize_pub_key (int *len, char *PUBKEY_FILE) {
    FILE *file = fopen(PUBKEY_FILE, "rb");
    if (file == NULL)
        handleErrors("ошибка при сериализации публичного ключа: PUBKEY_FILE open rb");

    *len = (int) get_file_size(PUBKEY_FILE);

    unsigned char *pubkey = (unsigned char *) malloc(*len);
    if (fread(pubkey, *len, 1, file) != 1)
        handleErrors("serialize: Не удалось считать файл публичного ключа");

    fclose(file);
    return pubkey;
}


// Наоборот: записываем строку публичного ключа в файл - десериализация:
void deserialize_pub_key (unsigned char* pubkey, int pubkey_len, char *PUBKEY_FILE) {
    FILE *file = fopen(PUBKEY_FILE, "wb");
    if (file == NULL)
        handleErrors("ошибка десериализации ключа: PUBKEY_FILE open wb");

    if (fwrite(pubkey, pubkey_len, 1, file) != 1)
        handleErrors("deserialize: Не удалось записать файл публичного ключа");

    fclose(file);
}