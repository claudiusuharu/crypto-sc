#include "rsa_gmp.h"
#include <gmp.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#define RSA_BLOCK_OVERHEAD 11  // PKCS#1 v1.5: 00 02 [random] 00 [data]
#define MAX_BLOCK_SIZE 512     // Supports up to 4096-bit keys

static void read_mpz_hex(mpz_t rop, FILE *f) {
    char buf[8192];
    fgets(buf, sizeof(buf), f);
    buf[strcspn(buf, "\r\n")] = 0;
    mpz_set_str(rop, buf, 16);
}

// Read key: n then e/d, both hex, one per line
static int read_key(const char *path, mpz_t n, mpz_t ed) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    read_mpz_hex(n, f);
    read_mpz_hex(ed, f);
    fclose(f);
    return 0;
}

// Fill buf with random nonzero bytes
static void random_nonzero_bytes(uint8_t *buf, size_t len) {
    FILE *urnd = fopen("/dev/urandom", "rb");
    for (size_t i = 0; i < len; ) {
        uint8_t b;
        if (urnd) fread(&b, 1, 1, urnd);
        else b = (uint8_t)(rand() % 0xFF + 1);
        if (b) buf[i++] = b;
    }
    if (urnd) fclose(urnd);
}

int rsa_gmp_encrypt(FILE *fin, FILE *fout, const char *pubkey_path) {
    mpz_t n, e, m, c;
    mpz_inits(n, e, m, c, NULL);
    if (read_key(pubkey_path, n, e) != 0) {
        fprintf(stderr, "No public key file\n");
        return 1;
    }
    size_t k = (mpz_sizeinbase(n, 2) + 7) / 8; // modulus size in bytes
    if (k > MAX_BLOCK_SIZE) { fprintf(stderr, "Key too large.\n"); return 1; }
    uint8_t bin[MAX_BLOCK_SIZE], enc[MAX_BLOCK_SIZE];
    size_t max_data = k - RSA_BLOCK_OVERHEAD;
    size_t r;
    while ((r = fread(bin, 1, max_data, fin)) > 0) {
        // PKCS#1 v1.5 pad: 00 02 [random nonzero] 00 [data]
        uint8_t padded[MAX_BLOCK_SIZE];
        padded[0] = 0x00; padded[1] = 0x02;
        random_nonzero_bytes(padded + 2, k - r - 3);
        padded[k - r - 1] = 0x00;
        memcpy(padded + k - r, bin, r);
        mpz_import(m, k, 1, 1, 0, 0, padded);
        if (mpz_cmp(m, n) >= 0) { fprintf(stderr, "Block >= modulus\n"); return 1; }
        mpz_powm(c, m, e, n);
        size_t w;
        mpz_export(enc, &w, 1, 1, 0, 0, c);
        // Write k bytes, pad with leading zeros if needed
        if (w < k) memset(bin, 0, k - w);
        memcpy(bin + k - w, enc, w);
        fwrite(bin, 1, k, fout);
    }
    mpz_clears(n, e, m, c, NULL);
    return 0;
}

int rsa_gmp_decrypt(FILE *fin, FILE *fout, const char *privkey_path) {
    mpz_t n, d, c, m;
    mpz_inits(n, d, c, m, NULL);
    if (read_key(privkey_path, n, d) != 0) {
        fprintf(stderr, "No private key file\n");
        return 1;
    }
    size_t k = (mpz_sizeinbase(n, 2) + 7) / 8;
    if (k > MAX_BLOCK_SIZE) { fprintf(stderr, "Key too large.\n"); return 1; }
    uint8_t in[MAX_BLOCK_SIZE], out[MAX_BLOCK_SIZE];
    size_t r;
    while ((r = fread(in, 1, k, fin)) == k) {
        mpz_import(c, k, 1, 1, 0, 0, in);
        mpz_powm(m, c, d, n);
        size_t count;
        mpz_export(out, &count, 1, 1, 0, 0, m);
        // Pad with leading zeros if needed
        if (count < k) memmove(out + (k - count), out, count), memset(out, 0, k - count);
        // Remove PKCS#1 v1.5: find after 00 02 ... 00
        size_t i = 2;
        while (i < k && out[i] != 0) ++i;
        if (i == k) continue; // error
        ++i;
        fwrite(out + i, 1, k - i, fout);
    }
    mpz_clears(n, d, c, m, NULL);
    return 0;
}