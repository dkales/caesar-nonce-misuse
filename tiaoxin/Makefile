CC=gcc
CFLAGS=-Wall -maes -msse4

all: tiaoxin-optimized.c helper.c main.c
	$(CC) $(CFLAGS) main.c helper.c tiaoxin-optimized.c -o attack

run: attack
	./attack
