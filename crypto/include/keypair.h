#pragma once

#include <openssl/evp.h>
#include <openssl/pem.h>

void key_gen(char* PUBKEY_FILE, char* PRIKEY_FILE, char* PRIKEY_PASSWD);
unsigned char* serialize_pub_key (int *len, char *PUBKEY_FILE);
void deserialize_pub_key (unsigned char* pubkey, int pubkey_len, char *file);