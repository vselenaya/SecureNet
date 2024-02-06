#pragma once

#include <stddef.h>

int is_file(char* file);
int min(int a, int b);
void handleErrors(const char *info);
void hex_dump (const char *info, const unsigned char *str, size_t len);