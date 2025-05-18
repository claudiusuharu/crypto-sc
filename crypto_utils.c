#include "crypto_utils.h"
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

int hex2bin(const char *hex, uint8_t *bin, size_t binlen) {
    size_t i;
    for (i = 0; i < binlen; ++i) {
        int hi = toupper(hex[2*i]);
        int lo = toupper(hex[2*i+1]);
        if (!isxdigit(hi) || !isxdigit(lo)) return -1;
        hi = hi > '9' ? hi - 'A' + 10 : hi - '0';
        lo = lo > '9' ? lo - 'A' + 10 : lo - '0';
        bin[i] = (hi << 4) | lo;
    }
    return 0;
}
int read_keyfile(const char *filename, uint8_t *buf, size_t buflen) {
    FILE *f = fopen(filename, "rb");
    if (!f) return -1;
    char hex[2*buflen+2];
    size_t r = fread(hex, 1, 2*buflen, f);
    fclose(f);
    if (r != 2*buflen) return -1;
    hex[r] = 0;
    return hex2bin(hex, buf, buflen);
}