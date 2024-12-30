#ifndef BEAMHASHVERIFY_H
#define BEAMHASHVERIFY_H

#include <stdint.h>
#include "crypto/beamHashIII.h"
#include "crypto/equihashR.h"
#include "beam/core/difficulty.h"
#include "beam/core/uintBig.h"

#include <sodium.h>

#include <vector>

#ifdef __cplusplus
extern "C" {
#endif

bool verifyBH(const char*, const char*, const std::vector<unsigned char>&, int pow);

#ifdef __cplusplus
}
#endif

#endif