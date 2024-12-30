#ifndef SCHNORR_H
#define SCHNORR_H

#include "secp256k1/include/secp256k1.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    secp256k1_context *schnorr_init();
    int schnorr_sign(secp256k1_context *ctx, const unsigned char *input, unsigned char *output, const unsigned char *key, uint32_t input_len);

#ifdef __cplusplus
}
#endif
#endif
