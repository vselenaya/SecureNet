#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "common.h"


// Функция проверки наличия файла file
int is_file(char* file) {
    FILE* f = fopen(file, "r");
    if (f == NULL)
        return 0;

    fclose(f);
    return 1;
}


// Функция минимума из a, b
int min(int a, int b) {
    if (a < b)
        return a;
    else
        return b;
}


// Функция обработки ошибок:
void handleErrors(const char *info) {
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "Дополнительная информация: %s\n", info);
    fprintf(stderr, "==========================\n");
    exit(1);  // после выхода операционная система автоматически освободит всю память,
              // так что можно при ошибке спокойно завершать программу
}


// Функция вывода шестнадцатиричного текста:
void hex_dump (const char *info, const unsigned char *str, size_t len) {
    printf("%s: ", info);  // выводим сначала ккую-то информацию
    for (size_t i = 0; i < len; ++i) printf("%02x ", str[i]);  // затем сами байты 
    printf("\n");
}