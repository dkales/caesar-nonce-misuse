CC=gcc
CFLAGS=-Wall

all: encrypt.c main.c
	$(CC) $(CFLAGS) main.c encrypt.c -o attack

run: attack
	./attack
