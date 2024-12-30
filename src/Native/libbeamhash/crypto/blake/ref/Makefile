CC=gcc
CFLAGS=-O2 -I../testvectors -Wall -Wextra -std=c89 -pedantic -Wno-long-long
BLAKEBINS=blake2b

all:		$(BLAKEBINS) check

blake2b:	blake2b-ref.c
		$(CC) blake2b-ref.c -o $@ $(CFLAGS) -DBLAKE2B_SELFTEST

check:          blake2b
	        ./blake2b

clean:
		rm -rf *.o $(BLAKEBINS)
