#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <string.h>
#include <openssl/hmac.h>

#include "common.h"


// Функция шифрования текста plaintext (как набора байт) длины plaintext_len в ciphertext
// с использованием ключа key и инициализационного вектора iv
// (шифрование блочным шифром AES-256 с режимом шифрования CBC)
int encrypt(unsigned char *plaintext, int plaintext_len, 
            unsigned char *key, unsigned char *iv, 
            unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))                                           handleErrors("encrypt ctx");  // создание и инициализация контекста
    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)          handleErrors("encrypt init");

    if(EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) handleErrors("encrypt");
    ciphertext_len = len;
    if(EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)                   handleErrors("encrypt final");
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


// Функция расшифровки:
int decrypt(unsigned char *ciphertext, int ciphertext_len, 
            unsigned char *key, unsigned char *iv, 
            unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;

    int len;
    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))                                            handleErrors("decrypt ctx");
    if(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)           handleErrors("decrypt init");
    
    if(EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) handleErrors("decrypt");
    plaintext_len = len;

    if(EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)                     handleErrors("decrypt final");
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}