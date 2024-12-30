// keccak.h
// 19-Nov-11  Markku-Juhani O. Saarinen <mjos@iki.fi>

#ifndef CRYPTONOTE_KECCAK_H
#define CRYPTONOTE_KECCAK_H

#include <stdint.h>
#include <string.h>

#ifndef CRYPTONOTE_KECCAK_ROUNDS
#define CRYPTONOTE_KECCAK_ROUNDS 24
#endif

#ifndef ROTL64
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))
#endif

// compute a keccak hash (md) of given byte length from "in"
int cryptonote_keccak(const uint8_t *in, int inlen, uint8_t *md, int mdlen);

// update the state
void cryptonote_keccakf(uint64_t st[25], int norounds);

void cryptonote_keccak1600(const uint8_t *in, int inlen, uint8_t *md);

#endif
