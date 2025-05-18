#include "chacha20.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROTL32(v, n) ((v << n) | (v >> (32 - n)))
#define QR(a, b, c, d)           \
    a += b; d ^= a; d = ROTL32(d,16); \
    c += d; b ^= c; b = ROTL32(b,12); \
    a += b; d ^= a; d = ROTL32(d, 8); \
    c += d; b ^= c; b = ROTL32(b, 7);

static const char sigma[16] = "expand 32-byte k";
static uint32_t U8TO32_LE(const uint8_t *p) {
    return ((uint32_t)p[0])       |
           ((uint32_t)p[1] << 8)  |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}
static void U32TO8_LE(uint8_t *p, uint32_t v) {
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
}
static void chacha20_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t out[64]) {
    uint32_t state[16], x[16];
    int i;
    state[0] = U8TO32_LE((const uint8_t *)&sigma[0]);
    state[1] = U8TO32_LE((const uint8_t *)&sigma[4]);
    state[2] = U8TO32_LE((const uint8_t *)&sigma[8]);
    state[3] = U8TO32_LE((const uint8_t *)&sigma[12]);
    for (i = 0; i < 8; i++)
        state[4 + i] = U8TO32_LE(key + i*4);
    state[12] = counter;
    state[13] = U8TO32_LE(nonce + 0);
    state[14] = U8TO32_LE(nonce + 4);
    state[15] = U8TO32_LE(nonce + 8);
    memcpy(x, state, sizeof(state));
    for (i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8], x[12]);
        QR(x[1], x[5], x[9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8], x[13]);
        QR(x[3], x[4], x[9], x[14]);
    }
    for (i = 0; i < 16; i++)
        x[i] += state[i];
    for (i = 0; i < 16; i++)
        U32TO8_LE(out + 4 * i, x[i]);
}
int chacha20_file_xor(FILE *fin, FILE *fout, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    uint8_t inbuf[64 * 1024], outbuf[64 * 1024];
    uint8_t keystream[64];
    size_t r, i, j, blocks;
    while ((r = fread(inbuf, 1, sizeof(inbuf), fin)) > 0) {
        blocks = r / 64;
        for (i = 0; i < blocks; ++i) {
            chacha20_block(key, nonce, counter++, keystream);
            for (j = 0; j < 64; ++j)
                outbuf[i*64 + j] = inbuf[i*64 + j] ^ keystream[j];
        }
        size_t rem = r % 64;
        if (rem) {
            chacha20_block(key, nonce, counter++, keystream);
            for (j = 0; j < rem; ++j)
                outbuf[blocks*64 + j] = inbuf[blocks*64 + j] ^ keystream[j];
        }
        if (fwrite(outbuf, 1, r, fout) != r) return -1;
    }
    return 0;
}