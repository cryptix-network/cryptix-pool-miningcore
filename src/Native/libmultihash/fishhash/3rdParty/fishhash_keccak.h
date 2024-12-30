#ifndef FISHHASH_KECCAK_H
#define FISHHASH_KECCAK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void fishash_keccak(uint64_t* out, size_t bits, const uint8_t* data, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* FISHHASH_KECCAK_H */
