#if defined(__aarch64__)
#include <arm_neon.h>

#include <bitset>

#include "include/fnv1a.h"
#include "include/xxhash64.h"
#include "include/highwayhash/sip_hash.h"
#include "astrobwtv3.h"

#include "include/lookup.h"

uint32_t branchComputeCPU_aarch64(RC4_KEY key, unsigned char *sData);
#endif