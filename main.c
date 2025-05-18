#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "chacha20.h"
#include "tea.h"
#include "crypto_utils.h"
#include "rsa_gmp.h"

void print_usage(const char *prog) {
    printf("Usage:\n");
    printf("  %s -e|-d -m chacha20|tea|rsa -i infile -k keyfile -o outfile [-n noncefile/ivfile]\n", prog);
    printf("Keyfile: hex (chacha20: 64 hex chars [32 bytes], tea: 32 hex chars [16 bytes], rsa: text with n/e or n/d in hex)\n");
    printf("Nonce/IV: hex (chacha20: 24 hex chars [12 bytes], tea: 16 hex chars [8 bytes])\n");
    printf("RSA keyfile: two lines of hex, n then e (public) or d (private)\n");
}

int main(int argc, char *argv[]) {
    int encrypt = -1;
    char method[16] = "", *infile=NULL, *outfile=NULL, *keyfile=NULL, *nfile=NULL;
    for (int i=1; i<argc; i++) {
        if (!strcmp(argv[i], "-e")) encrypt = 1;
        else if (!strcmp(argv[i], "-d")) encrypt = 0;
        else if (!strcmp(argv[i], "-m") && i+1<argc) strcpy(method, argv[++i]);
        else if (!strcmp(argv[i], "-i") && i+1<argc) infile = argv[++i];
        else if (!strcmp(argv[i], "-k") && i+1<argc) keyfile = argv[++i];
        else if (!strcmp(argv[i], "-o") && i+1<argc) outfile = argv[++i];
        else if (!strcmp(argv[i], "-n") && i+1<argc) nfile = argv[++i];
    }
    if (encrypt==-1 || !method[0] || !infile || !outfile || !keyfile) {
        print_usage(argv[0]);
        return 1;
    }
    FILE *fin = fopen(infile, "rb");
    FILE *fout = fopen(outfile, "wb");
    if (!fin || !fout) { printf("File error\n"); if(fin) fclose(fin); if(fout) fclose(fout); return 2; }
    if (!strcmp(method,"chacha20")) {
        uint8_t key[32], nonce[12];
        if (read_keyfile(keyfile, key, 32)<0) { printf("Keyfile error\n"); fclose(fin); fclose(fout); return 3; }
        if (!nfile) { puts("Nonce file required for chacha20!"); fclose(fin); fclose(fout); return 4; }
        if (read_keyfile(nfile, nonce, 12)<0) { printf("Nonce file error\n"); fclose(fin); fclose(fout); return 5; }
        int rc = chacha20_file_xor(fin, fout, key, nonce, 0);
        if (rc) printf("Error during chacha20 %sion!\n", encrypt?"encrypt":"decrypt");
        else printf("chacha20 %sion successful.\n", encrypt?"encrypt":"decrypt");
        fclose(fin); fclose(fout);
        return rc;
    } else if (!strcmp(method,"tea")) {
        uint8_t key[16], iv[8];
        if (read_keyfile(keyfile, key, 16)<0) { printf("Keyfile error\n"); fclose(fin); fclose(fout); return 6; }
        if (!nfile) { puts("IV file required for TEA!"); fclose(fin); fclose(fout); return 7; }
        if (read_keyfile(nfile, iv, 8)<0) { printf("IV file error\n"); fclose(fin); fclose(fout); return 8; }
        tea_cbc_encrypt(fin, fout, key, iv, encrypt);
        printf("TEA %sion successful.\n", encrypt?"encrypt":"decrypt");
        fclose(fin); fclose(fout);
        return 0;
    } else if (!strcmp(method,"rsa")) {
        int rc;
        if (encrypt)
            rc = rsa_gmp_encrypt(fin, fout, keyfile);
        else
            rc = rsa_gmp_decrypt(fin, fout, keyfile);
        if (rc)
            printf("RSA %sion error.\n", encrypt ? "encrypt" : "decrypt");
        else
            printf("RSA %sion successful.\n", encrypt ? "encrypt" : "decrypt");
        fclose(fin); fclose(fout);
        return rc;
    } else {
        printf("Unknown method '%s'.\n", method);
        print_usage(argv[0]);
        fclose(fin); fclose(fout);
        return 10;
    }
}