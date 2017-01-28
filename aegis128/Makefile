CC=gcc
CFLAGS=-Wall -maes -msse2

all: aes.c encrypt.c main.c
	$(CC) $(CFLAGS) main.c aes.c encrypt.c -o attack

run: attack
	./attack
