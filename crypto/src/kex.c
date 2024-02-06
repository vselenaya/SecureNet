#include <openssl/evp.h>
#include <openssl/ec.h>
#include <stdio.h>

#include "common.h"
#include "kex.h"

/*
Здесь реализуется самое волшебное место во всём шифрованном взаимодействии: выработка общего секрета.
Что имеется: имеется незащищенный канал связи (который могут читать все), а также клиент и сервер, которые
общаются только по этому каналу -> им необхоимо с помощью этого сгенерировать общий секрет, который знают только
они! Это кажется невозможно, но протокол Диффи-Хеллмана (ECDH) это делает.

Каждая сторона (клиент и сервер) генерируют пару ключей (открытый и закрытый) (оба этих ключа хранятся в одной
переменной pkey, возвращаемой из ecdh_pkey()), а затем отправляют друг другу только открытые ключи. В итоге
у сервера и у клиента будет по два открытых ключа (их могут перхватить кто-угодно, так как канал незащищён),
но также у них у каждого будет свой закрытый ключ (они, конечно, разные - уж какие сгенерировались). И вот
по этим ключам и клиент, и сервер генерируют секрет, который будет общим (он будет одинаковым для них).
*/


// Генерация ключей для одного пира (клиента или сервера):
// (то, что вернётся из функции - это pkey - в нём содержится открытый и закрытый ключ)
EVP_PKEY *ecdh_pkey() {
    EVP_PKEY_CTX *pctx, *kctx;
    EVP_PKEY *pkey = NULL, *params = NULL;

    if((pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) == NULL)
        handleErrors("pctx init");
    
    if(EVP_PKEY_paramgen_init(pctx) != 1)
        handleErrors("pctx init");
    if(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) != 1)
        handleErrors("curve");
    if(!EVP_PKEY_paramgen(pctx, &params))
        handleErrors("paramgen");
    if((kctx = EVP_PKEY_CTX_new(params, NULL)) == NULL)
        handleErrors("params");

    if(EVP_PKEY_keygen_init(kctx) != 1)
        handleErrors("keygen init");
    if(EVP_PKEY_keygen(kctx, &pkey) != 1)  // создаём ключи из контекста с параметром
        handleErrors("keygen");
    
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(pctx);

    return pkey;
}


// Сериализация публичного ключа, из полученного предыдущей функцией:
unsigned char *pubkey_put (EVP_PKEY *pkey, size_t *pubkey_len) {
    unsigned char *pubkey;
    *pubkey_len = i2d_PublicKey(pkey, NULL);  // используем специальную функцию openssl, чтобы из pkey достать только публичный ключ

    if((pubkey = OPENSSL_malloc(*pubkey_len)) == NULL)
        handleErrors("malloc");
    if(i2d_PublicKey(pkey, &pubkey) <= 0)
        handleErrors("i2d");
    
    return pubkey - *pubkey_len;
}


// Выроботка общего секрета из открытых ключей клиента и сервера:
unsigned char *ecdh_secret (EVP_PKEY *pkey,  // свой (клиентский) ключ (а точнее пара - открытый и закрытый)
                            unsigned char *pubkey, size_t pubkey_len,  // сериализованный (таким его из сокета достали) публичный ключ другого (сервера)
                            size_t *secret_len) {
        
    EVP_PKEY *peer_key = NULL;
    EVP_PKEY_CTX *pctx;

    if((pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) == NULL)
        handleErrors("peerctx init");    
    if(EVP_PKEY_paramgen_init(pctx) != 1)
        handleErrors("peerctx init");
    if(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) != 1)
        handleErrors("curve");
    if(!EVP_PKEY_paramgen(pctx, &peer_key))
        handleErrors("paramgen");

    const unsigned char *pk = pubkey;
    if (d2i_PublicKey(EVP_PKEY_EC, &peer_key, &pk, pubkey_len) == NULL)  // десериализуем публичный ключ сервера
        handleErrors("d2i");
    
    EVP_PKEY_CTX *ctx;
    if((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL)
        handleErrors("secret ctx");
    if(EVP_PKEY_derive_init(ctx) != 1)
        handleErrors("secret ctx init");
    if(EVP_PKEY_derive_set_peer(ctx, peer_key) != 1)
        handleErrors("peerkey ctx");

    unsigned char *secret;  // тут будет секретный ключ - точнее общий секрет  
    if(EVP_PKEY_derive(ctx, NULL, secret_len) != 1)
        handleErrors("secret len");
    if((secret = OPENSSL_malloc(*secret_len)) == NULL)
        handleErrors("secret malloc");
    if(EVP_PKEY_derive(ctx, secret, secret_len) <= 0)
        handleErrors("secret derive");

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(peer_key);

    return secret;
}