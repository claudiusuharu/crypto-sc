CC=gcc
CFLAGS=-Wall -O2

OBJS=main.o chacha20.o tea.o crypto_utils.o rsa_gmp.o

crypto: $(OBJS)
	$(CC) $(CFLAGS) -o crypto $(OBJS) -lgmp

main.o: main.c chacha20.h tea.h crypto_utils.h
chacha20.o: chacha20.c chacha20.h
tea.o: tea.c tea.h
crypto_utils.o: crypto_utils.c crypto_utils.h
rsa_gmp.o: rsa_gmp.c rsa_gmp.h

clean:
	rm -f *.o crypto