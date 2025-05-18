#ifndef RSA_GMP_H
#define RSA_GMP_H

#include <stdio.h>

// Encrypts fin to fout using public key in pubkey_path (format: n\ne\n)
int rsa_gmp_encrypt(FILE *fin, FILE *fout, const char *pubkey_path);

// Decrypts fin to fout using private key in privkey_path (format: n\nd\n)
int rsa_gmp_decrypt(FILE *fin, FILE *fout, const char *privkey_path);

#endif