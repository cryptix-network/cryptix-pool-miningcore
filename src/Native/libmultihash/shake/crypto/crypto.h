/**
 * @file crypto.h
 * @brief General definitions for cryptographic algorithms
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2023 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCRYPTO Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.3.0
 **/

#ifndef _CRYPTO_H
#define _CRYPTO_H

//Dependencies
#include "cpu_endian.h"


/*
 * CycloneCRYPTO Open is licensed under GPL version 2. In particular:
 *
 * - If you link your program to CycloneCRYPTO Open, the result is a derivative
 *   work that can only be distributed under the same GPL license terms.
 *
 * - If additions or changes to CycloneCRYPTO Open are made, the result is a
 *   derivative work that can only be distributed under the same license terms.
 *
 * - The GPL license requires that you make the source code available to
 *   whoever you make the binary available to.
 *
 * - If you sell or distribute a hardware product that runs CycloneCRYPTO Open,
 *   the GPL license requires you to provide public and full access to all
 *   source code on a nondiscriminatory basis.
 *
 * If you fully understand and accept the terms of the GPL license, then edit
 * the os_port_config.h header and add the following directive:
 *
 * #define GPL_LICENSE_TERMS_ACCEPTED
 */

#define GPL_LICENSE_TERMS_ACCEPTED

#ifndef GPL_LICENSE_TERMS_ACCEPTED
   #error Before compiling CycloneCRYPTO Open, you must accept the terms of the GPL license
#endif

//Version string
#define CYCLONE_CRYPTO_VERSION_STRING "2.3.0"
//Major version
#define CYCLONE_CRYPTO_MAJOR_VERSION 2
//Minor version
#define CYCLONE_CRYPTO_MINOR_VERSION 3
//Revision number
#define CYCLONE_CRYPTO_REV_NUMBER 0

// errors
#ifndef NO_ERROR
   #define NO_ERROR 0
#endif

#ifndef ERROR_OUT_OF_MEMORY
   #define ERROR_OUT_OF_MEMORY -1
#endif

#ifndef ERROR_INVALID_PARAMETER
   #define ERROR_INVALID_PARAMETER -2
#endif

//Rotate left operation
#define ROL8(a, n) (((a) << (n)) | ((a) >> (8 - (n))))
#define ROL16(a, n) (((a) << (n)) | ((a) >> (16 - (n))))
#define ROL32(a, n) (((a) << (n)) | ((a) >> (32 - (n))))
#define ROL64(a, n) (((a) << (n)) | ((a) >> (64 - (n))))

//Rotate right operation
#define ROR8(a, n) (((a) >> (n)) | ((a) << (8 - (n))))
#define ROR16(a, n) (((a) >> (n)) | ((a) << (16 - (n))))
#define ROR32(a, n) (((a) >> (n)) | ((a) << (32 - (n))))
#define ROR64(a, n) (((a) >> (n)) | ((a) << (64 - (n))))

//Shift left operation
#define SHL8(a, n) ((a) << (n))
#define SHL16(a, n) ((a) << (n))
#define SHL32(a, n) ((a) << (n))
#define SHL64(a, n) ((a) << (n))

//Shift right operation
#define SHR8(a, n) ((a) >> (n))
#define SHR16(a, n) ((a) >> (n))
#define SHR32(a, n) ((a) >> (n))
#define SHR64(a, n) ((a) >> (n))

//Micellaneous macros
#define _U8(x) ((uint8_t) (x))
#define _U16(x) ((uint16_t) (x))
#define _U32(x) ((uint32_tt) (x))
#define _U64(x) ((uint64_t) (x))

//Test if a 8-bit integer is zero
#define CRYPTO_TEST_Z_8(a) \
   _U8((_U8((_U8(a) | (~_U8(a) + 1U))) >> 7U) ^ 1U)

//Test if a 8-bit integer is nonzero
#define CRYPTO_TEST_NZ_8(a) \
   _U8(_U8((_U8(a) | (~_U8(a) + 1U))) >> 7U)

//Test if two 8-bit integers are equal
#define CRYPTO_TEST_EQ_8(a, b) \
   _U8((_U8(((_U8(a) ^ _U8(b)) | (~(_U8(a) ^ _U8(b)) + 1U))) >> 7U) ^ 1U)

//Test if two 8-bit integers are not equal
#define CRYPTO_TEST_NEQ_8(a, b) \
   _U8(_U8(((_U8(a) ^ _U8(b)) | (~(_U8(a) ^ _U8(b)) + 1U))) >> 7U)

//Test if a 8-bit integer is lower than another 8-bit integer
#define CRYPTO_TEST_LT_8(a, b) \
   _U8(_U8((((_U8(a) - _U8(b)) ^ _U8(b)) | (_U8(a) ^ _U8(b))) ^ _U8(a)) >> 7U)

//Test if a 8-bit integer is lower or equal than another 8-bit integer
#define CRYPTO_TEST_LTE_8(a, b) \
   _U8((_U8((((_U8(b) - _U8(a)) ^ _U8(a)) | (_U8(a) ^ _U8(b))) ^ _U8(b)) >> 7U) ^ 1U)

//Test if a 8-bit integer is greater than another 8-bit integer
#define CRYPTO_TEST_GT_8(a, b) \
   _U8(_U8((((_U8(b) - _U8(a)) ^ _U8(a)) | (_U8(a) ^ _U8(b))) ^ _U8(b)) >> 7U)

//Test if a 8-bit integer is greater or equal than another 8-bit integer
#define CRYPTO_TEST_GTE_8(a, b) \
   _U8((_U8((((_U8(a) - _U8(b)) ^ _U8(b)) | (_U8(a) ^ _U8(b))) ^ _U8(a)) >> 7U) ^ 1U)

//Select between two 8-bit integers
#define CRYPTO_SELECT_8(a, b, c) \
   _U8((_U8(a) & (_U8(c) - 1U)) | (_U8(b) & ~(_U8(c) - 1U)))

//Test if a 16-bit integer is zero
#define CRYPTO_TEST_Z_16(a) \
   _U16((_U16((_U16(a) | (~_U16(a) + 1U))) >> 15U) ^ 1U)

//Test if a 16-bit integer is nonzero
#define CRYPTO_TEST_NZ_16(a) \
   _U16(_U16((_U16(a) | (~_U16(a) + 1U))) >> 15U)

//Test if two 16-bit integers are equal
#define CRYPTO_TEST_EQ_16(a, b) \
   _U16((_U16(((_U16(a) ^ _U16(b)) | (~(_U16(a) ^ _U16(b)) + 1U))) >> 15U) ^ 1U)

//Test if two 16-bit integers are not equal
#define CRYPTO_TEST_NEQ_16(a, b) \
   _U16(_U16(((_U16(a) ^ _U16(b)) | (~(_U16(a) ^ _U16(b)) + 1U))) >> 15U)

//Test if a 16-bit integer is lower than another 16-bit integer
#define CRYPTO_TEST_LT_16(a, b) \
   _U16(_U16((((_U16(a) - _U16(b)) ^ _U16(b)) | (_U16(a) ^ _U16(b))) ^ _U16(a)) >> 15U)

//Test if a 16-bit integer is lower or equal than another 16-bit integer
#define CRYPTO_TEST_LTE_16(a, b) \
   _U16((_U16((((_U16(b) - _U16(a)) ^ _U16(a)) | (_U16(a) ^ _U16(b))) ^ _U16(b)) >> 15U) ^ 1U)

//Test if a 16-bit integer is greater than another 16-bit integer
#define CRYPTO_TEST_GT_16(a, b) \
   _U16(_U16((((_U16(b) - _U16(a)) ^ _U16(a)) | (_U16(a) ^ _U16(b))) ^ _U16(b)) >> 15U)

//Test if a 16-bit integer is greater or equal than another 16-bit integer
#define CRYPTO_TEST_GTE_16(a, b) \
   _U16((_U16((((_U16(a) - _U16(b)) ^ _U16(b)) | (_U16(a) ^ _U16(b))) ^ _U16(a)) >> 15U) ^ 1U)

//Select between two 16-bit integers
#define CRYPTO_SELECT_16(a, b, c) \
   _U16((_U16(a) & (_U16(c) - 1U)) | (_U16(b) & ~(_U16(c) - 1U)))

//Test if a 32-bit integer is zero
#define CRYPTO_TEST_Z_32(a) \
   _U32((_U32((_U32(a) | (~_U32(a) + 1U))) >> 31U) ^ 1U)

//Test if a 32-bit integer is nonzero
#define CRYPTO_TEST_NZ_32(a) \
   _U32(_U32((_U32(a) | (~_U32(a) + 1U))) >> 31U)

//Test if two 32-bit integers are equal
#define CRYPTO_TEST_EQ_32(a, b) \
   _U32((_U32(((_U32(a) ^ _U32(b)) | (~(_U32(a) ^ _U32(b)) + 1U))) >> 31U) ^ 1U)

//Test if two 32-bit integers are not equal
#define CRYPTO_TEST_NEQ_32(a, b) \
   _U32(_U32(((_U32(a) ^ _U32(b)) | (~(_U32(a) ^ _U32(b)) + 1U))) >> 31U)

//Test if a 32-bit integer is lower than another 32-bit integer
#define CRYPTO_TEST_LT_32(a, b) \
   _U32(_U32((((_U32(a) - _U32(b)) ^ _U32(b)) | (_U32(a) ^ _U32(b))) ^ _U32(a)) >> 31U)

//Test if a 32-bit integer is lower or equal than another 32-bit integer
#define CRYPTO_TEST_LTE_32(a, b) \
   _U32((_U32((((_U32(b) - _U32(a)) ^ _U32(a)) | (_U32(a) ^ _U32(b))) ^ _U32(b)) >> 31U) ^ 1U)

//Test if a 32-bit integer is greater than another 32-bit integer
#define CRYPTO_TEST_GT_32(a, b) \
   _U32(_U32((((_U32(b) - _U32(a)) ^ _U32(a)) | (_U32(a) ^ _U32(b))) ^ _U32(b)) >> 31U)

//Test if a 32-bit integer is greater or equal than another 32-bit integer
#define CRYPTO_TEST_GTE_32(a, b) \
   _U32((_U32((((_U32(a) - _U32(b)) ^ _U32(b)) | (_U32(a) ^ _U32(b))) ^ _U32(a)) >> 31U) ^ 1U)

//Select between two 32-bit integers
#define CRYPTO_SELECT_32(a, b, c) \
   _U32((_U32(a) & (_U32(c) - 1U)) | (_U32(b) & ~(_U32(c) - 1U)))

//Select between two 64-bit integers
#define CRYPTO_SELECT_64(a, b, c) \
   _U64((_U64(a) & (_U64(c) - 1U)) | (_U64(b) & ~(_U64(c) - 1U)))

//Forward declaration of PrngAlgo structure
struct _PrngAlgo;
#define PrngAlgo struct _PrngAlgo

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Encryption algorithm type
 **/

typedef enum
{
   CIPHER_ALGO_TYPE_STREAM = 0,
   CIPHER_ALGO_TYPE_BLOCK  = 1
} CipherAlgoType;


/**
 * @brief Cipher operation modes
 **/

typedef enum
{
   CIPHER_MODE_NULL              = 0,
   CIPHER_MODE_STREAM            = 1,
   CIPHER_MODE_ECB               = 2,
   CIPHER_MODE_CBC               = 3,
   CIPHER_MODE_CFB               = 4,
   CIPHER_MODE_OFB               = 5,
   CIPHER_MODE_CTR               = 6,
   CIPHER_MODE_CCM               = 7,
   CIPHER_MODE_GCM               = 8,
   CIPHER_MODE_CHACHA20_POLY1305 = 9,
} CipherMode;


//Common API for hash algorithms
typedef int (*HashAlgoCompute)(const void *data, size_t length,
   uint8_t *digest);

typedef void (*HashAlgoInit)(void *context);

typedef void (*HashAlgoUpdate)(void *context, const void *data, size_t length);

typedef void (*HashAlgoFinal)(void *context, uint8_t *digest);

typedef void (*HashAlgoFinalRaw)(void *context, uint8_t *digest);

//Common API for encryption algorithms
typedef int (*CipherAlgoInit)(void *context, const uint8_t *key,
   size_t keyLen);

typedef void (*CipherAlgoEncryptStream)(void *context, const uint8_t *input,
   uint8_t *output, size_t length);

typedef void (*CipherAlgoDecryptStream)(void *context, const uint8_t *input,
   uint8_t *output, size_t length);

typedef void (*CipherAlgoEncryptBlock)(void *context, const uint8_t *input,
   uint8_t *output);

typedef void (*CipherAlgoDecryptBlock)(void *context, const uint8_t *input,
   uint8_t *output);

typedef void (*CipherAlgoDeinit)(void *context);

//Common interface for key encapsulation mechanisms (KEM)
typedef int (*KemAlgoGenerateKeyPair)(const PrngAlgo *prngAlgo,
   void *prngContext, uint8_t *pk, uint8_t *sk);

typedef int (*KemAlgoEncapsulate)(const PrngAlgo *prngAlgo,
   void *prngContext, uint8_t *ct, uint8_t *ss, const uint8_t *pk);

typedef int (*KemAlgoDecapsulate)(uint8_t *ss, const uint8_t *ct,
   const uint8_t *sk);

//Common API for pseudo-random number generators (PRNG)
typedef int (*PrngAlgoInit)(void *context);

typedef int (*PrngAlgoSeed)(void *context, const uint8_t *input,
   size_t length);

typedef int (*PrngAlgoAddEntropy)(void *context, uint_t source,
   const uint8_t *input, size_t length, size_t entropy);

typedef int (*PrngAlgoRead)(void *context, uint8_t *output, size_t length);

typedef void (*PrngAlgoDeinit)(void *context);


/**
 * @brief Common interface for hash algorithms
 **/

typedef struct
{
   const char_t *name;
   const uint8_t *oid;
   size_t oidSize;
   size_t contextSize;
   size_t blockSize;
   size_t digestSize;
   size_t minPadSize;
   bool_t bigEndian;
   HashAlgoCompute compute;
   HashAlgoInit init;
   HashAlgoUpdate update;
   HashAlgoFinal final;
   HashAlgoFinalRaw finalRaw;
} HashAlgo;


/**
 * @brief Common interface for encryption algorithms
 **/

typedef struct
{
   const char_t *name;
   size_t contextSize;
   CipherAlgoType type;
   size_t blockSize;
   CipherAlgoInit init;
   CipherAlgoEncryptStream encryptStream;
   CipherAlgoDecryptStream decryptStream;
   CipherAlgoEncryptBlock encryptBlock;
   CipherAlgoDecryptBlock decryptBlock;
   CipherAlgoDeinit deinit;
} CipherAlgo;


/**
 * @brief Common interface for key encapsulation mechanisms (KEM)
 **/

typedef struct
{
   const char_t *name;
   size_t publicKeySize;
   size_t secretKeySize;
   size_t ciphertextSize;
   size_t sharedSecretSize;
   KemAlgoGenerateKeyPair generateKeyPair;
   KemAlgoEncapsulate encapsulate;
   KemAlgoDecapsulate decapsulate;
} KemAlgo;


/**
 * @brief Common interface for pseudo-random number generators (PRNG)
 **/

struct _PrngAlgo
{
   const char_t *name;
   size_t contextSize;
   PrngAlgoInit init;
   PrngAlgoSeed seed;
   PrngAlgoAddEntropy addEntropy;
   PrngAlgoRead read;
   PrngAlgoDeinit deinit;
};


//C++ guard
#ifdef __cplusplus
}
#endif

#endif
