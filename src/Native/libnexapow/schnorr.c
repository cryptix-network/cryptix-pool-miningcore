#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_schnorr.h"
#include "schnorr_random.h"
#include <stdint.h>

// schnorr_init initializes the secp256k1 context and randomizes it
// returns 1 on success, 0 on failure
secp256k1_context *schnorr_init()
{
    unsigned char randomize[32];

    // create the initial secp256k1 context
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    // file the randomize array with random bytes
    if (!fill_random(randomize, sizeof(randomize)))
    {
        printf("Failed to generate randomness\n");
        secp256k1_context_destroy(ctx);
        return NULL;
    }

    // randomize the context
    if (!secp256k1_context_randomize(ctx, randomize))
    {
        printf("Failed to randomize context\n");
        secp256k1_context_destroy(ctx);
        return NULL;
    }

    return ctx;
};

// schnorr_sign signs the input using the schnorr algorithm and writes the signature to output
// returns 1 on success, 0 on failure
int schnorr_sign(secp256k1_context *ctx, const unsigned char *input, unsigned char *output, const unsigned char *key, uint32_t input_len)
{
    if (input_len != 32)
    {
        printf("Input must be 32 bytes\n");
        return 0;
    }

    // verify that the input is a valid ecdsa secret key
    if (!secp256k1_ec_seckey_verify(ctx, key))
    {
        printf("Invalid secret key\n");
        return 0;
    }

    // sign the input with the secret key using the schnorr algorithm
    if (!secp256k1_schnorr_sign(ctx, output, input, key, secp256k1_nonce_function_rfc6979, NULL))
    {
        printf("Failed to sign\n");
        return 0;
    }

    return 1;
};
