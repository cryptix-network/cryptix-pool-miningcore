#include <stdint.h>
#include "secp256k1/include/secp256k1.h"
#include "schnorr.h"

#ifdef _WIN32
#define MODULE_API __declspec(dllexport)
#else
#define MODULE_API
#endif

extern "C" MODULE_API secp256k1_context *schnorr_init_export()
{
    return schnorr_init();
};

extern "C" MODULE_API int schnorr_sign_export(secp256k1_context *ctx, const unsigned char *input, unsigned char *output, const unsigned char *key, uint32_t input_len)
{
    return schnorr_sign(ctx, input, output, key, input_len);
}
