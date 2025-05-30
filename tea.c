#include "tea.h"
#include <stdint.h>
#include <string.h>

static void tea_encrypt_block(const uint8_t in[8], uint8_t out[8], const uint8_t key[16]) {
    uint32_t v0, v1, sum = 0, i;
    uint32_t k[4];
    v0 = ((uint32_t)in[0]<<24) | ((uint32_t)in[1]<<16) | ((uint32_t)in[2]<<8) | in[3];
    v1 = ((uint32_t)in[4]<<24) | ((uint32_t)in[5]<<16) | ((uint32_t)in[6]<<8) | in[7];
    for (i=0; i<4; i++) {
        k[i] = ((uint32_t)key[i*4]<<24) | ((uint32_t)key[i*4+1]<<16) | ((uint32_t)key[i*4+2]<<8) | key[i*4+3];
    }
    uint32_t delta = 0x9e3779b9;
    for (i = 0; i < 32; i++) {
        sum += delta;
        v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
    }
    out[0] = v0 >> 24; out[1] = v0 >> 16; out[2] = v0 >> 8; out[3] = v0;
    out[4] = v1 >> 24; out[5] = v1 >> 16; out[6] = v1 >> 8; out[7] = v1;
}

static void tea_decrypt_block(const uint8_t in[8], uint8_t out[8], const uint8_t key[16]) {
    uint32_t v0, v1, sum, i;
    uint32_t k[4];
    v0 = ((uint32_t)in[0]<<24) | ((uint32_t)in[1]<<16) | ((uint32_t)in[2]<<8) | in[3];
    v1 = ((uint32_t)in[4]<<24) | ((uint32_t)in[5]<<16) | ((uint32_t)in[6]<<8) | in[7];
    for (i=0; i<4; i++) {
        k[i] = ((uint32_t)key[i*4]<<24) | ((uint32_t)key[i*4+1]<<16) | ((uint32_t)key[i*4+2]<<8) | key[i*4+3];
    }
    uint32_t delta = 0x9e3779b9;
    sum = delta * 32;
    for (i = 0; i < 32; i++) {
        v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        sum -= delta;
    }
    out[0] = v0 >> 24; out[1] = v0 >> 16; out[2] = v0 >> 8; out[3] = v0;
    out[4] = v1 >> 24; out[5] = v1 >> 16; out[6] = v1 >> 8; out[7] = v1;
}

void tea_cbc_encrypt(FILE *fin, FILE *fout, const uint8_t key[16], const uint8_t iv[8], int enc) {
    uint8_t prev[8], in[8], out[8];
    size_t r, i;

    if (enc) {
        memcpy(prev, iv, 8);
        while ((r = fread(in, 1, 8, fin)) == 8) {
            for (i = 0; i < 8; i++) in[i] ^= prev[i];
            tea_encrypt_block(in, out, key);
            fwrite(out, 1, 8, fout);
            memcpy(prev, out, 8);
        }
        uint8_t pad = 8 - r;
        for (i = r; i < 8; i++) in[i] = pad;
        for (i = 0; i < 8; i++) in[i] ^= prev[i];
        tea_encrypt_block(in, out, key);
        fwrite(out, 1, 8, fout);
    } else {
        memcpy(prev, iv, 8);
        fseek(fin, 0, SEEK_END);
        long total = ftell(fin);
        fseek(fin, 0, SEEK_SET);
        long blocks = total / 8;
        for (long blk = 0; blk < blocks; blk++) {
            r = fread(in, 1, 8, fin);
            if (r != 8) break;
            tea_decrypt_block(in, out, key);
            for (i = 0; i < 8; i++) out[i] ^= prev[i];
            if (blk == blocks - 1) {
                uint8_t pad = out[7];
                if (pad == 0 || pad > 8) pad = 8;
                fwrite(out, 1, 8 - pad, fout);
            } else {
                fwrite(out, 1, 8, fout);
                memcpy(prev, in, 8);
            }
            if (blk < blocks - 1) memcpy(prev, in, 8);
        }
    }
}
