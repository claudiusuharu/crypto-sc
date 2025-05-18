#ifndef TEA_H
#define TEA_H
#include <stdint.h>
#include <stdio.h>
void tea_cbc_encrypt(FILE *fin, FILE *fout, const uint8_t key[16], const uint8_t iv[8], int enc);
#endif