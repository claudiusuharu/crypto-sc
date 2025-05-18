#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H
#include <stdint.h>
#include <stddef.h>
int hex2bin(const char *hex, uint8_t *bin, size_t binlen);
int read_keyfile(const char *filename, uint8_t *buf, size_t buflen);
#endif