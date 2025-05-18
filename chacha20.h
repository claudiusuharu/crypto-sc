#ifndef CHACHA20_H
#define CHACHA20_H
#include <stdint.h>
#include <stdio.h>
int chacha20_file_xor(FILE *fin, FILE *fout, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter);
#endif