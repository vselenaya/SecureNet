#pragma once

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <stdio.h>

EVP_PKEY *ecdh_pkey();
unsigned char *pubkey_put (EVP_PKEY *pkey, size_t *pubkey_len);
unsigned char *ecdh_secret (EVP_PKEY *pkey,
                            unsigned char *pubkey, size_t pubkey_len,
                            size_t *secret_len);