#include "include/endian.hpp"
#include "include/fnv1a.h"
#include "include/xxhash64.h"
#include "astrobwtv3.h"
#include "include/highwayhash/sip_hash.h"
#include "include/lookup.h"

#if defined(__x86_64__)
  #include <xmmintrin.h>
  #include <emmintrin.h>
#endif
#if defined(__aarch64__)
  #include "astro_aarch64.hpp"
#endif

void hashSHA256(SHA256_CTX &sha256, const unsigned char *input, unsigned char *digest, unsigned long inputSize)
{
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, input, inputSize);
  SHA256_Final(digest, &sha256);
}

void AstroBWTv3(const unsigned char *input, int inputLen, unsigned char *outputhash)
{
  try
  {
    //void * ctx = libsais_create_ctx();
    unsigned char sData[MAX_LENGTH+64];
    SHA256_CTX sha256;
    unsigned char salsaInput[256] = {0};
    ucstk::Salsa20 salsa20;
    RC4_KEY key = {};
    int32_t sa[MAX_LENGTH];
    //int bA[256];
    //int bB[256*256];
    unsigned char sHash[32];
    uint32_t data_len;

    std::fill_n(sData + 256, 64, 0);
    memset(sData + 256, 0, 64);

    __builtin_prefetch(&sData[256], 1, 3);
    __builtin_prefetch(&sData[256+64], 1, 3);
    __builtin_prefetch(&sData[256+128], 1, 3);
    __builtin_prefetch(&sData[256+192], 1, 3);

    hashSHA256(sha256, input, &sData[320], inputLen);
    salsa20.setKey(&sData[320]);
    salsa20.setIv(&sData[256]);

    __builtin_prefetch(&sData, 1, 3);
    __builtin_prefetch(&sData[64], 1, 3);
    __builtin_prefetch(&sData[128], 1, 3);
    __builtin_prefetch(&sData[192], 1, 3);

    salsa20.processBytes(salsaInput, sData, 256);

    //__builtin_prefetch(&key + 8, 1, 3);
    //__builtin_prefetch(&key + 8+64, 1, 3);
    //__builtin_prefetch(&key + 8+128, 1, 3);
    //__builtin_prefetch(&key + 8+192, 1, 3);

    RC4_set_key(&key, 256,  sData);
    RC4(&key, 256, sData, sData);

    #if defined(__AVX2__)
        //data_len = branchComputeCPU_avx2(key, sData);
        data_len = wolfCompute(key, sData);
    #elif defined(__aarch64__)
        data_len = branchComputeCPU_aarch64(key, sData);
    #else
        data_len = branchComputeCPU(key, sData);
    #endif

    // divsufsort(sData, sa, data_len, bA, bB);
    libsais(sData, sa, data_len, MAX_LENGTH-data_len, NULL);

    if (littleEndian())
    {
      unsigned char *B = reinterpret_cast<unsigned char *>(sa);
      hashSHA256(sha256, B, sHash, data_len*4);
      // sHash = nHash;
    }
    else
    {
      unsigned char *s = new unsigned char[MAX_LENGTH * 4];
      for (int i = 0; i < data_len; i++)
      {
        s[i << 1] = htonl(sa[i]);
      }
      hashSHA256(sha256, s, sHash, data_len*4);
      // sHash = nHash;
      delete[] s;
    }
    memcpy(outputhash, sHash, 32);
    // memset(outputhash, 0xFF, 32);
  }
  catch (const std::exception &ex)
  {
    // recover(outputhash);
    std::cerr << ex.what() << std::endl;
  }
}

uint32_t branchComputeCPU(RC4_KEY key, unsigned char *sData)
{
  uint64_t lhash = hash_64_fnv1a_256(sData);
  uint64_t prev_lhash = lhash;

  unsigned char *prev_chunk;
  unsigned char *chunk;

  uint64_t tries = 0;

  while (true)
  {
    tries++;
    uint64_t random_switcher = prev_lhash ^ lhash ^ tries;

    unsigned char op = static_cast<unsigned char>(random_switcher);

    unsigned char pos1 = static_cast<unsigned char>(random_switcher >> 8);
    unsigned char pos2 = static_cast<unsigned char>(random_switcher >> 16);

    if (pos1 > pos2)
    {
      std::swap(pos1, pos2);
    }

    if (pos2 - pos1 > 32)
    {
      pos2 = pos1 + ((pos2 - pos1) & 0x1f);
    }

    chunk = &sData[(tries - 1) * 256];

    if (tries == 1) {
      prev_chunk = chunk;
    } else {
      prev_chunk = &sData[(tries - 2) * 256];
    }

    memcpy(chunk, prev_chunk, 256);

    switch (op)
    {
    case 0:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
        chunk[i] = rl8(chunk[i], 5);                // rotate  bits by 5
        chunk[i] *= chunk[i];                             // *
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random

        // INSERT_RANDOM_CODE_END
        unsigned char t1 = chunk[pos1];
        unsigned char t2 = chunk[pos2];
        chunk[pos1] = reverse8(t2);
        chunk[pos2] = reverse8(t1);
      }
      break;
    case 1:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
        chunk[i] = rl8(chunk[i], 1);                // rotate  bits by 1
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] += chunk[i];                             // +
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 2:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];          // ones count bits
        chunk[i] = reverse8(chunk[i]);                 // reverse bits
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];          // ones count bits
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 3:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = rl8(chunk[i], 3);                // rotate  bits by 3
        chunk[i] ^= chunk[pos2];                   // XOR
        chunk[i] = rl8(chunk[i], 1);                // rotate  bits by 1
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 4:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = ~chunk[i];                             // binary NOT operator
        chunk[i] = chunk[i] >> (chunk[i] & 3);    // shift right
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] -= (chunk[i] ^ 97);                      // XOR and -
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 5:
    {
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {

        // INSERT_RANDOM_CODE_START
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];          // ones count bits
        chunk[i] ^= chunk[pos2];                // XOR
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right

        // INSERT_RANDOM_CODE_END
      }
    }
    break;
    case 6:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] = rl8(chunk[i], 3);             // rotate  bits by 3
        chunk[i] = ~chunk[i];                          // binary NOT operator
        chunk[i] -= (chunk[i] ^ 97);                   // XOR and -

        // INSERT_RANDOM_CODE_END
      }
      break;
    case 7:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] += chunk[i];                             // +
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
        chunk[i] = ~chunk[i];                             // binary NOT operator
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 8:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = ~chunk[i];               // binary NOT operator
        chunk[i] = rl8(chunk[i], 10); // rotate  bits by 5
        // chunk[i] = rl8(chunk[i], 5);// rotate  bits by 5
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 9:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= chunk[pos2];                // XOR
        chunk[i] ^= rl8(chunk[i], 4);            // rotate  bits by 4
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] ^= rl8(chunk[i], 2);            // rotate  bits by 2
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 10:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = ~chunk[i];              // binary NOT operator
        chunk[i] *= chunk[i];              // *
        chunk[i] = rl8(chunk[i], 3); // rotate  bits by 3
        chunk[i] *= chunk[i];              // *
                                                           // INSERT_RANDOM_CODE_END
      }
      break;
    case 11:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 6); // rotate  bits by 1
        // chunk[i] = rl8(chunk[i], 5);            // rotate  bits by 5
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 12:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
        chunk[i] *= chunk[i];               // *
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
        chunk[i] = ~chunk[i];               // binary NOT operator
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 13:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 1);             // rotate  bits by 1
        chunk[i] ^= chunk[pos2];                // XOR
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] = rl8(chunk[i], 5);             // rotate  bits by 5
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 14:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] *= chunk[i];                          // *
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 15:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] -= (chunk[i] ^ 97);                      // XOR and -
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 16:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 4); // rotate  bits by 4
        chunk[i] *= chunk[i];               // *
        chunk[i] = rl8(chunk[i], 1);  // rotate  bits by 1
        chunk[i] = ~chunk[i];               // binary NOT operator
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 17:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= chunk[pos2];    // XOR
        chunk[i] *= chunk[i];              // *
        chunk[i] = rl8(chunk[i], 5); // rotate  bits by 5
        chunk[i] = ~chunk[i];              // binary NOT operator
                                                           // INSERT_RANDOM_CODE_END
      }
      break;
    case 18:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 4); // rotate  bits by 4
        chunk[i] = rl8(chunk[i], 9);  // rotate  bits by 3
        // chunk[i] = rl8(chunk[i], 1);             // rotate  bits by 1
        // chunk[i] = rl8(chunk[i], 5);         // rotate  bits by 5
        // INSERT_RANDOM_CODE_END
      }
      break;
    case 19:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] -= (chunk[i] ^ 97);                   // XOR and -
        chunk[i] = rl8(chunk[i], 5);             // rotate  bits by 5
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] += chunk[i];                          // +
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 20:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] ^= chunk[pos2];                   // XOR
        chunk[i] = reverse8(chunk[i]);                    // reverse bits
        chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 21:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 1);                // rotate  bits by 1
        chunk[i] ^= chunk[pos2];                   // XOR
        chunk[i] += chunk[i];                             // +
        chunk[i] = chunk[i] & chunk[pos2]; // AND
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 22:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] = reverse8(chunk[i]);                 // reverse bits
        chunk[i] *= chunk[i];                          // *
        chunk[i] = rl8(chunk[i], 1);             // rotate  bits by 1
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 23:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 4); // rotate  bits by 3
        // chunk[i] = rl8(chunk[i], 1);                           // rotate  bits by 1
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
        chunk[i] = chunk[i] & chunk[pos2]; // AND
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 24:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] += chunk[i];                          // +
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] ^= rl8(chunk[i], 4);            // rotate  bits by 4
        chunk[i] = rl8(chunk[i], 5);             // rotate  bits by 5
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 25:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
        chunk[i] = rl8(chunk[i], 3);                // rotate  bits by 3
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] -= (chunk[i] ^ 97);                      // XOR and -
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 26:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] *= chunk[i];                 // *
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] += chunk[i];                 // +
        chunk[i] = reverse8(chunk[i]);        // reverse bits
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 27:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 5);                // rotate  bits by 5
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] ^= rl8(chunk[i], 4);               // rotate  bits by 4
        chunk[i] = rl8(chunk[i], 5);                // rotate  bits by 5
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 28:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] += chunk[i];                          // +
        chunk[i] += chunk[i];                          // +
        chunk[i] = rl8(chunk[i], 5);             // rotate  bits by 5
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 29:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] *= chunk[i];                          // *
        chunk[i] ^= chunk[pos2];                // XOR
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] += chunk[i];                          // +
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 30:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] ^= rl8(chunk[i], 4);               // rotate  bits by 4
        chunk[i] = rl8(chunk[i], 5);                // rotate  bits by 5
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 31:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = ~chunk[i];                          // binary NOT operator
        chunk[i] ^= rl8(chunk[i], 2);            // rotate  bits by 2
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] *= chunk[i];                          // *
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 32:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
        chunk[i] = reverse8(chunk[i]);      // reverse bits
        chunk[i] = rl8(chunk[i], 3);  // rotate  bits by 3
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 33:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] ^= rl8(chunk[i], 4);               // rotate  bits by 4
        chunk[i] = reverse8(chunk[i]);                    // reverse bits
        chunk[i] *= chunk[i];                             // *
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 34:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] -= (chunk[i] ^ 97);                   // XOR and -
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] -= (chunk[i] ^ 97);                   // XOR and -
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 35:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] += chunk[i];              // +
        chunk[i] = ~chunk[i];              // binary NOT operator
        chunk[i] = rl8(chunk[i], 1); // rotate  bits by 1
        chunk[i] ^= chunk[pos2];    // XOR
                                                           // INSERT_RANDOM_CODE_END
      }
      break;
    case 36:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] = rl8(chunk[i], 1);    // rotate  bits by 1
        chunk[i] ^= rl8(chunk[i], 2);   // rotate  bits by 2
        chunk[i] = rl8(chunk[i], 1);    // rotate  bits by 1
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 37:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = chunk[i] >> (chunk[i] & 3);    // shift right
        chunk[i] = chunk[i] >> (chunk[i] & 3);    // shift right
        chunk[i] *= chunk[i];                             // *
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 38:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] >> (chunk[i] & 3);    // shift right
        chunk[i] = rl8(chunk[i], 3);                // rotate  bits by 3
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 39:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
        chunk[i] ^= chunk[pos2];                   // XOR
        chunk[i] = chunk[i] >> (chunk[i] & 3);    // shift right
        chunk[i] = chunk[i] & chunk[pos2]; // AND
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 40:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] ^= chunk[pos2];                   // XOR
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
        chunk[i] ^= chunk[pos2];                   // XOR
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 41:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 5);  // rotate  bits by 5
        chunk[i] -= (chunk[i] ^ 97);        // XOR and -
        chunk[i] = rl8(chunk[i], 3);  // rotate  bits by 3
        chunk[i] ^= rl8(chunk[i], 4); // rotate  bits by 4
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 42:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 4); // rotate  bits by 1
        // chunk[i] = rl8(chunk[i], 3);                // rotate  bits by 3
        chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 43:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] += chunk[i];                             // +
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] -= (chunk[i] ^ 97);                      // XOR and -
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 44:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
        chunk[i] = rl8(chunk[i], 3);                // rotate  bits by 3
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 45:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 10); // rotate  bits by 5
        // chunk[i] = rl8(chunk[i], 5);                       // rotate  bits by 5
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 46:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] += chunk[i];                 // +
        chunk[i] = rl8(chunk[i], 5);    // rotate  bits by 5
        chunk[i] ^= rl8(chunk[i], 4);   // rotate  bits by 4
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 47:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 5);                // rotate  bits by 5
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] = rl8(chunk[i], 5);                // rotate  bits by 5
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 48:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        // chunk[i] = ~chunk[i];                    // binary NOT operator
        // chunk[i] = ~chunk[i];                    // binary NOT operator
        chunk[i] = rl8(chunk[i], 5); // rotate  bits by 5
                                                           // INSERT_RANDOM_CODE_END
      }
      break;
    case 49:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] += chunk[i];                 // +
        chunk[i] = reverse8(chunk[i]);        // reverse bits
        chunk[i] ^= rl8(chunk[i], 4);   // rotate  bits by 4
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 50:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = reverse8(chunk[i]);     // reverse bits
        chunk[i] = rl8(chunk[i], 3); // rotate  bits by 3
        chunk[i] += chunk[i];              // +
        chunk[i] = rl8(chunk[i], 1); // rotate  bits by 1
                                                           // INSERT_RANDOM_CODE_END
      }
      break;
    case 51:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= chunk[pos2];     // XOR
        chunk[i] ^= rl8(chunk[i], 4); // rotate  bits by 4
        chunk[i] ^= rl8(chunk[i], 4); // rotate  bits by 4
        chunk[i] = rl8(chunk[i], 5);  // rotate  bits by 5
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 52:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = chunk[i] >> (chunk[i] & 3);    // shift right
        chunk[i] = ~chunk[i];                             // binary NOT operator
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 53:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] += chunk[i];                 // +
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] ^= rl8(chunk[i], 4);   // rotate  bits by 4
        chunk[i] ^= rl8(chunk[i], 4);   // rotate  bits by 4
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 54:

#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = reverse8(chunk[i]);  // reverse bits
        chunk[i] ^= chunk[pos2]; // XOR
        // chunk[i] = ~chunk[i];    // binary NOT operator
        // chunk[i] = ~chunk[i];    // binary NOT operator
        // INSERT_RANDOM_CODE_END
      }

      break;
    case 55:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = reverse8(chunk[i]);      // reverse bits
        chunk[i] ^= rl8(chunk[i], 4); // rotate  bits by 4
        chunk[i] ^= rl8(chunk[i], 4); // rotate  bits by 4
        chunk[i] = rl8(chunk[i], 1);  // rotate  bits by 1
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 56:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
        chunk[i] *= chunk[i];               // *
        chunk[i] = ~chunk[i];               // binary NOT operator
        chunk[i] = rl8(chunk[i], 1);  // rotate  bits by 1
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 57:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = rl8(chunk[i], 8);                // rotate  bits by 5
        // chunk[i] = rl8(chunk[i], 3);                // rotate  bits by 3
        chunk[i] = reverse8(chunk[i]); // reverse bits
                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 58:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = reverse8(chunk[i]);                    // reverse bits
        chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] += chunk[i];                             // +
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 59:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 1);                // rotate  bits by 1
        chunk[i] *= chunk[i];                             // *
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = ~chunk[i];                             // binary NOT operator
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 60:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= chunk[pos2];    // XOR
        chunk[i] = ~chunk[i];              // binary NOT operator
        chunk[i] *= chunk[i];              // *
        chunk[i] = rl8(chunk[i], 3); // rotate  bits by 3
                                                           // INSERT_RANDOM_CODE_END
      }
      break;
    case 61:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 5);             // rotate  bits by 5
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] = rl8(chunk[i], 8);             // rotate  bits by 3
        // chunk[i] = rl8(chunk[i], 5);// rotate  bits by 5
        // INSERT_RANDOM_CODE_END
      }
      break;
    case 62:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] = ~chunk[i];                             // binary NOT operator
        chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
        chunk[i] += chunk[i];                             // +
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 63:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 5);    // rotate  bits by 5
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] -= (chunk[i] ^ 97);          // XOR and -
        chunk[i] += chunk[i];                 // +
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 64:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= chunk[pos2];     // XOR
        chunk[i] = reverse8(chunk[i]);      // reverse bits
        chunk[i] ^= rl8(chunk[i], 4); // rotate  bits by 4
        chunk[i] *= chunk[i];               // *
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 65:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 8); // rotate  bits by 5
        // chunk[i] = rl8(chunk[i], 3);             // rotate  bits by 3
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
        chunk[i] *= chunk[i];               // *
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 66:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
        chunk[i] = reverse8(chunk[i]);      // reverse bits
        chunk[i] ^= rl8(chunk[i], 4); // rotate  bits by 4
        chunk[i] = rl8(chunk[i], 1);  // rotate  bits by 1
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 67:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 1);    // rotate  bits by 1
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] ^= rl8(chunk[i], 2);   // rotate  bits by 2
        chunk[i] = rl8(chunk[i], 5);    // rotate  bits by 5
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 68:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] = ~chunk[i];                             // binary NOT operator
        chunk[i] ^= rl8(chunk[i], 4);               // rotate  bits by 4
        chunk[i] ^= chunk[pos2];                   // XOR
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 69:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] += chunk[i];                          // +
        chunk[i] *= chunk[i];                          // *
        chunk[i] = reverse8(chunk[i]);                 // reverse bits
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 70:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= chunk[pos2];                // XOR
        chunk[i] *= chunk[i];                          // *
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] ^= rl8(chunk[i], 4);            // rotate  bits by 4
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 71:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 5);             // rotate  bits by 5
        chunk[i] = ~chunk[i];                          // binary NOT operator
        chunk[i] *= chunk[i];                          // *
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 72:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = reverse8(chunk[i]);                 // reverse bits
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];          // ones count bits
        chunk[i] ^= chunk[pos2];                // XOR
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 73:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] = reverse8(chunk[i]);        // reverse bits
        chunk[i] = rl8(chunk[i], 5);    // rotate  bits by 5
        chunk[i] -= (chunk[i] ^ 97);          // XOR and -
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 74:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] *= chunk[i];                             // *
        chunk[i] = rl8(chunk[i], 3);                // rotate  bits by 3
        chunk[i] = reverse8(chunk[i]);                    // reverse bits
        chunk[i] = chunk[i] & chunk[pos2]; // AND
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 75:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] *= chunk[i];                             // *
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] ^= rl8(chunk[i], 4);               // rotate  bits by 4
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 76:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
        chunk[i] = rl8(chunk[i], 5);                // rotate  bits by 5
        chunk[i] = chunk[i] >> (chunk[i] & 3);    // shift right
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 77:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 3);             // rotate  bits by 3
        chunk[i] += chunk[i];                          // +
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];          // ones count bits
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 78:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = reverse8(chunk[i]);                    // reverse bits
        chunk[i] *= chunk[i];                             // *
        chunk[i] -= (chunk[i] ^ 97);                      // XOR and -
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 79:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 4); // rotate  bits by 4
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
        chunk[i] += chunk[i];               // +
        chunk[i] *= chunk[i];               // *
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 80:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
        chunk[i] += chunk[i];                             // +
        chunk[i] = chunk[i] & chunk[pos2]; // AND
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 81:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 4);               // rotate  bits by 4
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 82:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= chunk[pos2]; // XOR
        // chunk[i] = ~chunk[i];        // binary NOT operator
        // chunk[i] = ~chunk[i];        // binary NOT operator
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 83:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] = reverse8(chunk[i]);                 // reverse bits
        chunk[i] = rl8(chunk[i], 3);             // rotate  bits by 3
        chunk[i] = reverse8(chunk[i]);                 // reverse bits
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 84:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] -= (chunk[i] ^ 97);                   // XOR and -
        chunk[i] = rl8(chunk[i], 1);             // rotate  bits by 1
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] += chunk[i];                          // +
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 85:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] >> (chunk[i] & 3);    // shift right
        chunk[i] ^= chunk[pos2];                   // XOR
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 86:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 4);               // rotate  bits by 4
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] ^= rl8(chunk[i], 4);               // rotate  bits by 4
        chunk[i] = ~chunk[i];                             // binary NOT operator
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 87:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] += chunk[i];               // +
        chunk[i] = rl8(chunk[i], 3);  // rotate  bits by 3
        chunk[i] ^= rl8(chunk[i], 4); // rotate  bits by 4
        chunk[i] += chunk[i];               // +
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 88:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
        chunk[i] = rl8(chunk[i], 1);  // rotate  bits by 1
        chunk[i] *= chunk[i];               // *
        chunk[i] = ~chunk[i];               // binary NOT operator
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 89:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] += chunk[i];               // +
        chunk[i] *= chunk[i];               // *
        chunk[i] = ~chunk[i];               // binary NOT operator
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 90:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = reverse8(chunk[i]);     // reverse bits
        chunk[i] = rl8(chunk[i], 6); // rotate  bits by 5
        // chunk[i] = rl8(chunk[i], 1);    // rotate  bits by 1
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 91:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] ^= rl8(chunk[i], 4);               // rotate  bits by 4
        chunk[i] = reverse8(chunk[i]);                    // reverse bits
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 92:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
        chunk[i] = ~chunk[i];                             // binary NOT operator
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
        chunk[i] = chunk[i] & chunk[pos2]; // AND
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 93:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
        chunk[i] *= chunk[i];                             // *
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] += chunk[i];                             // +
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 94:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 1);                // rotate  bits by 1
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 95:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 1);  // rotate  bits by 1
        chunk[i] = ~chunk[i];               // binary NOT operator
        chunk[i] = rl8(chunk[i], 10); // rotate  bits by 5
        // chunk[i] = rl8(chunk[i], 5); // rotate  bits by 5
        // INSERT_RANDOM_CODE_END
      }
      break;
    case 96:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 2);   // rotate  bits by 2
        chunk[i] ^= rl8(chunk[i], 2);   // rotate  bits by 2
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] = rl8(chunk[i], 1);    // rotate  bits by 1
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 97:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 1);             // rotate  bits by 1
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];          // ones count bits
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 98:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 4);            // rotate  bits by 4
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] ^= rl8(chunk[i], 4);            // rotate  bits by 4
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 99:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 4);            // rotate  bits by 4
        chunk[i] -= (chunk[i] ^ 97);                   // XOR and -
        chunk[i] = reverse8(chunk[i]);                 // reverse bits
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 100:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
        chunk[i] = reverse8(chunk[i]);                    // reverse bits
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 101:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];          // ones count bits
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] = ~chunk[i];                          // binary NOT operator
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 102:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 3); // rotate  bits by 3
        chunk[i] -= (chunk[i] ^ 97);       // XOR and -
        chunk[i] += chunk[i];              // +
        chunk[i] = rl8(chunk[i], 3); // rotate  bits by 3
                                                           // INSERT_RANDOM_CODE_END
      }
      break;
    case 103:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 1);                // rotate  bits by 1
        chunk[i] = reverse8(chunk[i]);                    // reverse bits
        chunk[i] ^= chunk[pos2];                   // XOR
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 104:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = reverse8(chunk[i]);        // reverse bits
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] = rl8(chunk[i], 5);    // rotate  bits by 5
        chunk[i] += chunk[i];                 // +
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 105:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
        chunk[i] = rl8(chunk[i], 3);                // rotate  bits by 3
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 106:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = reverse8(chunk[i]);      // reverse bits
        chunk[i] ^= rl8(chunk[i], 4); // rotate  bits by 4
        chunk[i] = rl8(chunk[i], 1);  // rotate  bits by 1
        chunk[i] *= chunk[i];               // *
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 107:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] ^= rl8(chunk[i], 2);            // rotate  bits by 2
        chunk[i] = rl8(chunk[i], 6);             // rotate  bits by 5
        // chunk[i] = rl8(chunk[i], 1);             // rotate  bits by 1
        // INSERT_RANDOM_CODE_END
      }
      break;
    case 108:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= chunk[pos2];                   // XOR
        chunk[i] = ~chunk[i];                             // binary NOT operator
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 109:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] *= chunk[i];                             // *
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] ^= chunk[pos2];                   // XOR
        chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 110:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] += chunk[i];                          // +
        chunk[i] ^= rl8(chunk[i], 2);            // rotate  bits by 2
        chunk[i] ^= rl8(chunk[i], 2);            // rotate  bits by 2
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 111:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] *= chunk[i];                          // *
        chunk[i] = reverse8(chunk[i]);                 // reverse bits
        chunk[i] *= chunk[i];                          // *
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 112:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 3); // rotate  bits by 3
        chunk[i] = ~chunk[i];              // binary NOT operator
        chunk[i] = rl8(chunk[i], 5); // rotate  bits by 5
        chunk[i] -= (chunk[i] ^ 97);       // XOR and -
                                                           // INSERT_RANDOM_CODE_END
      }
      break;
    case 113:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 6); // rotate  bits by 5
        // chunk[i] = rl8(chunk[i], 1);                           // rotate  bits by 1
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] = ~chunk[i];                 // binary NOT operator
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 114:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 1);                // rotate  bits by 1
        chunk[i] = reverse8(chunk[i]);                    // reverse bits
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = ~chunk[i];                             // binary NOT operator
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 115:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = rl8(chunk[i], 5);                // rotate  bits by 5
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] = rl8(chunk[i], 3);                // rotate  bits by 3
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 116:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] ^= chunk[pos2];                   // XOR
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 117:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
        chunk[i] = rl8(chunk[i], 3);                // rotate  bits by 3
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
        chunk[i] = chunk[i] & chunk[pos2]; // AND
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 118:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] += chunk[i];                          // +
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] = rl8(chunk[i], 5);             // rotate  bits by 5
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 119:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = reverse8(chunk[i]);      // reverse bits
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
        chunk[i] = ~chunk[i];               // binary NOT operator
        chunk[i] ^= chunk[pos2];     // XOR
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 120:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
        chunk[i] *= chunk[i];               // *
        chunk[i] ^= chunk[pos2];     // XOR
        chunk[i] = reverse8(chunk[i]);      // reverse bits
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 121:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] += chunk[i];                          // +
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];          // ones count bits
        chunk[i] *= chunk[i];                          // *
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 122:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 4);               // rotate  bits by 4
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = rl8(chunk[i], 5);                // rotate  bits by 5
        chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 123:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] = ~chunk[i];                             // binary NOT operator
        chunk[i] = rl8(chunk[i], 6);                // rotate  bits by 3
        // chunk[i] = rl8(chunk[i], 3); // rotate  bits by 3
        // INSERT_RANDOM_CODE_END
      }
      break;
    case 124:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
        chunk[i] ^= chunk[pos2];     // XOR
        chunk[i] = ~chunk[i];               // binary NOT operator
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 125:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = reverse8(chunk[i]);                 // reverse bits
        chunk[i] ^= rl8(chunk[i], 2);            // rotate  bits by 2
        chunk[i] += chunk[i];                          // +
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 126:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 9); // rotate  bits by 3
        // chunk[i] = rl8(chunk[i], 1); // rotate  bits by 1
        // chunk[i] = rl8(chunk[i], 5); // rotate  bits by 5
        chunk[i] = reverse8(chunk[i]); // reverse bits
                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 127:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
        chunk[i] *= chunk[i];                             // *
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] ^= chunk[pos2];                   // XOR
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 128:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
        chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
        chunk[i] = rl8(chunk[i], 5);                // rotate  bits by 5
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 129:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = ~chunk[i];                          // binary NOT operator
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];          // ones count bits
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];          // ones count bits
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 130:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] >> (chunk[i] & 3);    // shift right
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = rl8(chunk[i], 1);                // rotate  bits by 1
        chunk[i] ^= rl8(chunk[i], 4);               // rotate  bits by 4
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 131:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] -= (chunk[i] ^ 97);          // XOR and -
        chunk[i] = rl8(chunk[i], 1);    // rotate  bits by 1
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] *= chunk[i];                 // *
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 132:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] = reverse8(chunk[i]);                    // reverse bits
        chunk[i] = rl8(chunk[i], 5);                // rotate  bits by 5
        chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 133:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= chunk[pos2];                // XOR
        chunk[i] = rl8(chunk[i], 5);             // rotate  bits by 5
        chunk[i] ^= rl8(chunk[i], 2);            // rotate  bits by 2
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 134:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = ~chunk[i];                             // binary NOT operator
        chunk[i] ^= rl8(chunk[i], 4);               // rotate  bits by 4
        chunk[i] = rl8(chunk[i], 1);                // rotate  bits by 1
        chunk[i] = chunk[i] & chunk[pos2]; // AND
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 135:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] ^= rl8(chunk[i], 2);            // rotate  bits by 2
        chunk[i] += chunk[i];                          // +
        chunk[i] = reverse8(chunk[i]);                 // reverse bits
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 136:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] -= (chunk[i] ^ 97);                   // XOR and -
        chunk[i] ^= chunk[pos2];                // XOR
        chunk[i] = rl8(chunk[i], 5);             // rotate  bits by 5
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 137:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 5);                // rotate  bits by 5
        chunk[i] = chunk[i] >> (chunk[i] & 3);    // shift right
        chunk[i] = reverse8(chunk[i]);                    // reverse bits
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 138:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= chunk[pos2]; // XOR
        chunk[i] ^= chunk[pos2]; // XOR
        chunk[i] += chunk[i];           // +
        chunk[i] -= (chunk[i] ^ 97);    // XOR and -
                                                        // INSERT_RANDOM_CODE_END
      }
      break;
    case 139:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 8); // rotate  bits by 5
        // chunk[i] = rl8(chunk[i], 3);             // rotate  bits by 3
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
        chunk[i] = rl8(chunk[i], 3);  // rotate  bits by 3
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 140:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 1);  // rotate  bits by 1
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
        chunk[i] ^= chunk[pos2];     // XOR
        chunk[i] = rl8(chunk[i], 5);  // rotate  bits by 5
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 141:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 1);    // rotate  bits by 1
        chunk[i] -= (chunk[i] ^ 97);          // XOR and -
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] += chunk[i];                 // +
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 142:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] = rl8(chunk[i], 5);                // rotate  bits by 5
        chunk[i] = reverse8(chunk[i]);                    // reverse bits
        chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 143:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] = rl8(chunk[i], 3);                // rotate  bits by 3
        chunk[i] = chunk[i] >> (chunk[i] & 3);    // shift right
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 144:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
        chunk[i] = ~chunk[i];                             // binary NOT operator
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 145:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = reverse8(chunk[i]);      // reverse bits
        chunk[i] ^= rl8(chunk[i], 4); // rotate  bits by 4
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
        chunk[i] ^= rl8(chunk[i], 4); // rotate  bits by 4
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 146:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 147:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = ~chunk[i];                          // binary NOT operator
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] ^= rl8(chunk[i], 4);            // rotate  bits by 4
        chunk[i] *= chunk[i];                          // *
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 148:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] = rl8(chunk[i], 5);                // rotate  bits by 5
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
        chunk[i] -= (chunk[i] ^ 97);                      // XOR and -
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 149:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= chunk[pos2]; // XOR
        chunk[i] = reverse8(chunk[i]);  // reverse bits
        chunk[i] -= (chunk[i] ^ 97);    // XOR and -
        chunk[i] += chunk[i];           // +
                                                        // INSERT_RANDOM_CODE_END
      }
      break;
    case 150:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
        chunk[i] = chunk[i] & chunk[pos2]; // AND
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 151:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] += chunk[i];                          // +
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] *= chunk[i];                          // *
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 152:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] = ~chunk[i];                          // binary NOT operator
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] ^= rl8(chunk[i], 2);            // rotate  bits by 2
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 153:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 4); // rotate  bits by 1
        // chunk[i] = rl8(chunk[i], 3); // rotate  bits by 3
        // chunk[i] = ~chunk[i];     // binary NOT operator
        // chunk[i] = ~chunk[i];     // binary NOT operator
        // INSERT_RANDOM_CODE_END
      }
      break;
    case 154:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 5);    // rotate  bits by 5
        chunk[i] = ~chunk[i];                 // binary NOT operator
        chunk[i] ^= chunk[pos2];       // XOR
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 155:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] -= (chunk[i] ^ 97);          // XOR and -
        chunk[i] ^= chunk[pos2];       // XOR
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] ^= chunk[pos2];       // XOR
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 156:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] = rl8(chunk[i], 4);             // rotate  bits by 3
        // chunk[i] = rl8(chunk[i], 1);    // rotate  bits by 1
        // INSERT_RANDOM_CODE_END
      }
      break;
    case 157:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] >> (chunk[i] & 3);    // shift right
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = rl8(chunk[i], 1);                // rotate  bits by 1
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 158:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] = rl8(chunk[i], 3);    // rotate  bits by 3
        chunk[i] += chunk[i];                 // +
        chunk[i] = rl8(chunk[i], 1);    // rotate  bits by 1
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 159:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] -= (chunk[i] ^ 97);                      // XOR and -
        chunk[i] ^= chunk[pos2];                   // XOR
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] ^= chunk[pos2];                   // XOR
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 160:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] = reverse8(chunk[i]);                 // reverse bits
        chunk[i] = rl8(chunk[i], 4);             // rotate  bits by 1
        // chunk[i] = rl8(chunk[i], 3);    // rotate  bits by 3
        // INSERT_RANDOM_CODE_END
      }
      break;
    case 161:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= chunk[pos2];                   // XOR
        chunk[i] ^= chunk[pos2];                   // XOR
        chunk[i] = rl8(chunk[i], 5);                // rotate  bits by 5
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 162:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] *= chunk[i];               // *
        chunk[i] = reverse8(chunk[i]);      // reverse bits
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
        chunk[i] -= (chunk[i] ^ 97);        // XOR and -
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 163:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] -= (chunk[i] ^ 97);                   // XOR and -
        chunk[i] ^= rl8(chunk[i], 4);            // rotate  bits by 4
        chunk[i] = rl8(chunk[i], 1);             // rotate  bits by 1
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 164:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] *= chunk[i];                 // *
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] -= (chunk[i] ^ 97);          // XOR and -
        chunk[i] = ~chunk[i];                 // binary NOT operator
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 165:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 4);            // rotate  bits by 4
        chunk[i] ^= chunk[pos2];                // XOR
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] += chunk[i];                          // +
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 166:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 3);  // rotate  bits by 3
        chunk[i] += chunk[i];               // +
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
        chunk[i] = ~chunk[i];               // binary NOT operator
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 167:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        // chunk[i] = ~chunk[i];        // binary NOT operator
        // chunk[i] = ~chunk[i];        // binary NOT operator
        chunk[i] *= chunk[i];                          // *
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 168:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = rl8(chunk[i], 1);                // rotate  bits by 1
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 169:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 1);                // rotate  bits by 1
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
        chunk[i] ^= rl8(chunk[i], 4);               // rotate  bits by 4
        chunk[i] = chunk[i] & chunk[pos2]; // AND
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 170:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] -= (chunk[i] ^ 97);   // XOR and -
        chunk[i] = reverse8(chunk[i]); // reverse bits
        chunk[i] -= (chunk[i] ^ 97);   // XOR and -
        chunk[i] *= chunk[i];          // *
                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 171:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 3);    // rotate  bits by 3
        chunk[i] -= (chunk[i] ^ 97);          // XOR and -
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] = reverse8(chunk[i]);        // reverse bits
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 172:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 4);            // rotate  bits by 4
        chunk[i] -= (chunk[i] ^ 97);                   // XOR and -
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] = rl8(chunk[i], 1);             // rotate  bits by 1
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 173:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = ~chunk[i];                          // binary NOT operator
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] *= chunk[i];                          // *
        chunk[i] += chunk[i];                          // +
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 174:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = ~chunk[i];                             // binary NOT operator
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 175:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 3); // rotate  bits by 3
        chunk[i] -= (chunk[i] ^ 97);       // XOR and -
        chunk[i] *= chunk[i];              // *
        chunk[i] = rl8(chunk[i], 5); // rotate  bits by 5
                                                           // INSERT_RANDOM_CODE_END
      }
      break;
    case 176:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= chunk[pos2];    // XOR
        chunk[i] *= chunk[i];              // *
        chunk[i] ^= chunk[pos2];    // XOR
        chunk[i] = rl8(chunk[i], 5); // rotate  bits by 5
                                                           // INSERT_RANDOM_CODE_END
      }
      break;
    case 177:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
        chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
        chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
        chunk[i] = chunk[i] & chunk[pos2]; // AND
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 178:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] += chunk[i];                             // +
        chunk[i] = ~chunk[i];                             // binary NOT operator
        chunk[i] = rl8(chunk[i], 1);                // rotate  bits by 1
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 179:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 2);            // rotate  bits by 2
        chunk[i] += chunk[i];                          // +
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] = reverse8(chunk[i]);                 // reverse bits
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 180:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] ^= rl8(chunk[i], 4);            // rotate  bits by 4
        chunk[i] ^= chunk[pos2];                // XOR
        chunk[i] -= (chunk[i] ^ 97);                   // XOR and -
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 181:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = ~chunk[i];                          // binary NOT operator
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] ^= rl8(chunk[i], 2);            // rotate  bits by 2
        chunk[i] = rl8(chunk[i], 5);             // rotate  bits by 5
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 182:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= chunk[pos2];    // XOR
        chunk[i] = rl8(chunk[i], 6); // rotate  bits by 1
        // chunk[i] = rl8(chunk[i], 5);         // rotate  bits by 5
        chunk[i] ^= rl8(chunk[i], 4); // rotate  bits by 4
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 183:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] += chunk[i];        // +
        chunk[i] -= (chunk[i] ^ 97); // XOR and -
        chunk[i] -= (chunk[i] ^ 97); // XOR and -
        chunk[i] *= chunk[i];        // *
                                                     // INSERT_RANDOM_CODE_END
      }
      break;
    case 184:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] *= chunk[i];                          // *
        chunk[i] = rl8(chunk[i], 5);             // rotate  bits by 5
        chunk[i] ^= chunk[pos2];                // XOR
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 185:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = ~chunk[i];                          // binary NOT operator
        chunk[i] ^= rl8(chunk[i], 4);            // rotate  bits by 4
        chunk[i] = rl8(chunk[i], 5);             // rotate  bits by 5
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 186:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 2);            // rotate  bits by 2
        chunk[i] ^= rl8(chunk[i], 4);            // rotate  bits by 4
        chunk[i] -= (chunk[i] ^ 97);                   // XOR and -
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 187:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= chunk[pos2];    // XOR
        chunk[i] = ~chunk[i];              // binary NOT operator
        chunk[i] += chunk[i];              // +
        chunk[i] = rl8(chunk[i], 3); // rotate  bits by 3
                                                           // INSERT_RANDOM_CODE_END
      }
      break;
    case 188:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 4);   // rotate  bits by 4
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] ^= rl8(chunk[i], 4);   // rotate  bits by 4
        chunk[i] ^= rl8(chunk[i], 4);   // rotate  bits by 4
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 189:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 5);  // rotate  bits by 5
        chunk[i] ^= rl8(chunk[i], 4); // rotate  bits by 4
        chunk[i] ^= chunk[pos2];     // XOR
        chunk[i] -= (chunk[i] ^ 97);        // XOR and -
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 190:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 5);                // rotate  bits by 5
        chunk[i] = chunk[i] >> (chunk[i] & 3);    // shift right
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 191:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] += chunk[i];                             // +
        chunk[i] = rl8(chunk[i], 3);                // rotate  bits by 3
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = chunk[i] >> (chunk[i] & 3);    // shift right
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 192:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] += chunk[i];                          // +
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] += chunk[i];                          // +
        chunk[i] *= chunk[i];                          // *
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 193:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = rl8(chunk[i], 1);                // rotate  bits by 1
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 194:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
        chunk[i] = chunk[i] & chunk[pos2]; // AND
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 195:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] ^= rl8(chunk[i], 2);   // rotate  bits by 2
        chunk[i] ^= chunk[pos2];       // XOR
        chunk[i] ^= rl8(chunk[i], 4);   // rotate  bits by 4
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 196:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 3);             // rotate  bits by 3
        chunk[i] = reverse8(chunk[i]);                 // reverse bits
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] = rl8(chunk[i], 1);             // rotate  bits by 1
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 197:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 4);               // rotate  bits by 4
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] *= chunk[i];                             // *
        chunk[i] *= chunk[i];                             // *
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 198:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] = reverse8(chunk[i]);                 // reverse bits
        chunk[i] = rl8(chunk[i], 1);             // rotate  bits by 1
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 199:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = ~chunk[i];           // binary NOT operator
        chunk[i] += chunk[i];           // +
        chunk[i] *= chunk[i];           // *
        chunk[i] ^= chunk[pos2]; // XOR
                                                        // INSERT_RANDOM_CODE_END
      }
      break;
    case 200:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];          // ones count bits
        chunk[i] = reverse8(chunk[i]);                 // reverse bits
        chunk[i] = reverse8(chunk[i]);                 // reverse bits
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 201:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 3);  // rotate  bits by 3
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
        chunk[i] ^= rl8(chunk[i], 4); // rotate  bits by 4
        chunk[i] = ~chunk[i];               // binary NOT operator
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 202:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= chunk[pos2];                   // XOR
        chunk[i] = ~chunk[i];                             // binary NOT operator
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = rl8(chunk[i], 5);                // rotate  bits by 5
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 203:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= chunk[pos2];                   // XOR
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] = rl8(chunk[i], 1);                // rotate  bits by 1
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 204:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 5);                // rotate  bits by 5
        chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] ^= chunk[pos2];                   // XOR
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 205:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];          // ones count bits
        chunk[i] ^= rl8(chunk[i], 4);            // rotate  bits by 4
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] += chunk[i];                          // +
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 206:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 4);   // rotate  bits by 4
        chunk[i] = reverse8(chunk[i]);        // reverse bits
        chunk[i] = reverse8(chunk[i]);        // reverse bits
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 207:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 8); // rotate  bits by 5
        // chunk[i] = rl8(chunk[i], 3);                           // rotate  bits by 3
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 208:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] += chunk[i];                          // +
        chunk[i] += chunk[i];                          // +
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] = rl8(chunk[i], 3);             // rotate  bits by 3
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 209:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 5);    // rotate  bits by 5
        chunk[i] = reverse8(chunk[i]);        // reverse bits
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] -= (chunk[i] ^ 97);          // XOR and -
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 210:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = rl8(chunk[i], 5);                // rotate  bits by 5
        chunk[i] = ~chunk[i];                             // binary NOT operator
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 211:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 4);               // rotate  bits by 4
        chunk[i] += chunk[i];                             // +
        chunk[i] -= (chunk[i] ^ 97);                      // XOR and -
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 212:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
        chunk[i] ^= chunk[pos2];                   // XOR
        chunk[i] ^= chunk[pos2];                   // XOR
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 213:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] += chunk[i];                          // +
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] = rl8(chunk[i], 3);             // rotate  bits by 3
        chunk[i] -= (chunk[i] ^ 97);                   // XOR and -
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 214:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= chunk[pos2];                // XOR
        chunk[i] -= (chunk[i] ^ 97);                   // XOR and -
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] = ~chunk[i];                          // binary NOT operator
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 215:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= chunk[pos2];                   // XOR
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
        chunk[i] *= chunk[i];                             // *
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 216:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = ~chunk[i];                             // binary NOT operator
        chunk[i] -= (chunk[i] ^ 97);                      // XOR and -
        chunk[i] = chunk[i] & chunk[pos2]; // AND
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 217:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 5);  // rotate  bits by 5
        chunk[i] += chunk[i];               // +
        chunk[i] = rl8(chunk[i], 1);  // rotate  bits by 1
        chunk[i] ^= rl8(chunk[i], 4); // rotate  bits by 4
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 218:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = reverse8(chunk[i]); // reverse bits
        chunk[i] = ~chunk[i];          // binary NOT operator
        chunk[i] *= chunk[i];          // *
        chunk[i] -= (chunk[i] ^ 97);   // XOR and -
                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 219:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 4);               // rotate  bits by 4
        chunk[i] = rl8(chunk[i], 3);                // rotate  bits by 3
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] = reverse8(chunk[i]);                    // reverse bits
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 220:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 1);             // rotate  bits by 1
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] = reverse8(chunk[i]);                 // reverse bits
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 221:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 5); // rotate  bits by 5
        chunk[i] ^= chunk[pos2];    // XOR
        chunk[i] = ~chunk[i];              // binary NOT operator
        chunk[i] = reverse8(chunk[i]);     // reverse bits
                                                           // INSERT_RANDOM_CODE_END
      }
      break;
    case 222:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] ^= chunk[pos2];                // XOR
        chunk[i] *= chunk[i];                          // *
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 223:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 3);                // rotate  bits by 3
        chunk[i] ^= chunk[pos2];                   // XOR
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] -= (chunk[i] ^ 97);                      // XOR and -
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 224:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
        chunk[i] = rl8(chunk[i], 4);  // rotate  bits by 1
        // chunk[i] = rl8(chunk[i], 3);             // rotate  bits by 3
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
                                                                       //
      }
      break;
    case 225:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = ~chunk[i];                          // binary NOT operator
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] = reverse8(chunk[i]);                 // reverse bits
        chunk[i] = rl8(chunk[i], 3);             // rotate  bits by 3
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 226:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = reverse8(chunk[i]);  // reverse bits
        chunk[i] -= (chunk[i] ^ 97);    // XOR and -
        chunk[i] *= chunk[i];           // *
        chunk[i] ^= chunk[pos2]; // XOR
                                                        // INSERT_RANDOM_CODE_END
      }
      break;
    case 227:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = ~chunk[i];                             // binary NOT operator
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
        chunk[i] -= (chunk[i] ^ 97);                      // XOR and -
        chunk[i] = chunk[i] & chunk[pos2]; // AND
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 228:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] += chunk[i];                          // +
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] += chunk[i];                          // +
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];          // ones count bits
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 229:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 3);                // rotate  bits by 3
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 230:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] *= chunk[i];                             // *
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 231:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 3);             // rotate  bits by 3
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] ^= chunk[pos2];                // XOR
        chunk[i] = reverse8(chunk[i]);                 // reverse bits
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 232:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] *= chunk[i];               // *
        chunk[i] *= chunk[i];               // *
        chunk[i] ^= rl8(chunk[i], 4); // rotate  bits by 4
        chunk[i] = rl8(chunk[i], 5);  // rotate  bits by 5
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 233:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 1);    // rotate  bits by 1
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] = rl8(chunk[i], 3);    // rotate  bits by 3
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 234:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] *= chunk[i];                             // *
        chunk[i] = chunk[i] >> (chunk[i] & 3);    // shift right
        chunk[i] ^= chunk[pos2];                   // XOR
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 235:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
        chunk[i] *= chunk[i];               // *
        chunk[i] = rl8(chunk[i], 3);  // rotate  bits by 3
        chunk[i] = ~chunk[i];               // binary NOT operator
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 236:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= chunk[pos2];                   // XOR
        chunk[i] += chunk[i];                             // +
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] -= (chunk[i] ^ 97);                      // XOR and -
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 237:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 5);             // rotate  bits by 5
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
        chunk[i] ^= rl8(chunk[i], 2);            // rotate  bits by 2
        chunk[i] = rl8(chunk[i], 3);             // rotate  bits by 3
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 238:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] += chunk[i];              // +
        chunk[i] += chunk[i];              // +
        chunk[i] = rl8(chunk[i], 3); // rotate  bits by 3
        chunk[i] -= (chunk[i] ^ 97);       // XOR and -
                                                           // INSERT_RANDOM_CODE_END
      }
      break;
    case 239:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 6); // rotate  bits by 5
        // chunk[i] = rl8(chunk[i], 1); // rotate  bits by 1
        chunk[i] *= chunk[i];                             // *
        chunk[i] = chunk[i] & chunk[pos2]; // AND
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 240:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = ~chunk[i];                             // binary NOT operator
        chunk[i] += chunk[i];                             // +
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] = chunk[i] << (chunk[i] & 3);    // shift left
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 241:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= rl8(chunk[i], 4);   // rotate  bits by 4
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] ^= chunk[pos2];       // XOR
        chunk[i] = rl8(chunk[i], 1);    // rotate  bits by 1
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 242:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] += chunk[i];           // +
        chunk[i] += chunk[i];           // +
        chunk[i] -= (chunk[i] ^ 97);    // XOR and -
        chunk[i] ^= chunk[pos2]; // XOR
                                                        // INSERT_RANDOM_CODE_END
      }
      break;
    case 243:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 5);    // rotate  bits by 5
        chunk[i] ^= rl8(chunk[i], 2);   // rotate  bits by 2
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] = rl8(chunk[i], 1);    // rotate  bits by 1
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 244:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = ~chunk[i];               // binary NOT operator
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
        chunk[i] = reverse8(chunk[i]);      // reverse bits
        chunk[i] = rl8(chunk[i], 5);  // rotate  bits by 5
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 245:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] -= (chunk[i] ^ 97);                   // XOR and -
        chunk[i] = rl8(chunk[i], 5);             // rotate  bits by 5
        chunk[i] ^= rl8(chunk[i], 2);            // rotate  bits by 2
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 246:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] += chunk[i];                          // +
        chunk[i] = rl8(chunk[i], 1);             // rotate  bits by 1
        chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
        chunk[i] += chunk[i];                          // +
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 247:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 5);  // rotate  bits by 5
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
        chunk[i] = rl8(chunk[i], 5);  // rotate  bits by 5
        chunk[i] = ~chunk[i];               // binary NOT operator
                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    case 248:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = ~chunk[i];                 // binary NOT operator
        chunk[i] -= (chunk[i] ^ 97);          // XOR and -
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] = rl8(chunk[i], 5);    // rotate  bits by 5
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 249:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = reverse8(chunk[i]);                    // reverse bits
        chunk[i] ^= rl8(chunk[i], 4);               // rotate  bits by 4
        chunk[i] ^= rl8(chunk[i], 4);               // rotate  bits by 4
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 250:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = chunk[i] & chunk[pos2]; // AND
        chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
        chunk[i] ^= rl8(chunk[i], 4);               // rotate  bits by 4
                                                                          // INSERT_RANDOM_CODE_END
      }
      break;
    case 251:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] += chunk[i];                 // +
        chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
        chunk[i] = reverse8(chunk[i]);        // reverse bits
        chunk[i] ^= rl8(chunk[i], 2);   // rotate  bits by 2
                                                              // INSERT_RANDOM_CODE_END
      }
      break;
    case 252:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = reverse8(chunk[i]);                 // reverse bits
        chunk[i] ^= rl8(chunk[i], 4);            // rotate  bits by 4
        chunk[i] ^= rl8(chunk[i], 2);            // rotate  bits by 2
        chunk[i] = chunk[i] << (chunk[i] & 3); // shift left
                                                                       // INSERT_RANDOM_CODE_END
      }
      break;
    case 253:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = rl8(chunk[i], 3);  // rotate  bits by 3
        chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
        chunk[i] ^= chunk[pos2];     // XOR
        chunk[i] = rl8(chunk[i], 3);  // rotate  bits by 3
        // INSERT_RANDOM_CODE_END

        prev_lhash = lhash + prev_lhash;
        lhash = XXHash64::hash(chunk, pos2,0);
      }
      break;
    case 254:
    case 255:
      RC4_set_key(&key, 256,  chunk);
// chunk = highwayhash.Sum(chunk[:], chunk[:])
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= static_cast<uint8_t>(std::bitset<8>(chunk[i]).count()); // ones count bits
        chunk[i] = rl8(chunk[i], 3);                                  // rotate  bits by 3
        chunk[i] ^= rl8(chunk[i], 2);                                 // rotate  bits by 2
        chunk[i] = rl8(chunk[i], 3);                                  // rotate  bits by 3
                                                                                            // INSERT_RANDOM_CODE_END
      }
      break;
    default:
      break;
    }

    unsigned char A = (chunk[pos1] - chunk[pos2]);
    A = (256 + (A % 256)) % 256;

    if (A < 0x10)
    { // 6.25 % probability
      __builtin_prefetch(chunk, 0, 0);
      prev_lhash = lhash + prev_lhash;
      lhash = XXHash64::hash(chunk, pos2, 0);
    }

    if (A < 0x20)
    { // 12.5 % probability
      __builtin_prefetch(chunk, 0, 0);
      prev_lhash = lhash + prev_lhash;
      lhash = hash_64_fnv1a(chunk, pos2);
    }

    if (A < 0x30)
    { // 18.75 % probability
      __builtin_prefetch(chunk, 0, 0);
      prev_lhash = lhash + prev_lhash;
      HH_ALIGNAS(16)
      const highwayhash::HH_U64 key2[2] = {tries, prev_lhash};
      lhash = highwayhash::SipHash(key2, (char*)chunk, pos2); // more deviations
    }

    if (A <= 0x40)
    { // 25% probablility
      //__builtin_prefetch(&key, 0, 0);
      RC4(&key, 256, chunk,  chunk);
    }

    chunk[255] = chunk[255] ^ chunk[pos1] ^ chunk[pos2];

    prefetch(chunk, 256, 1);
    memcpy(&sData[(tries - 1) * 256], chunk, 256);

    if (tries > 260 + 16 || (chunk[255] >= 0xf0 && tries > 260))
    {
      break;
    }
  }
  uint32_t data_len = static_cast<uint32_t>((tries - 4) * 256 + (((static_cast<uint64_t>(chunk[253]) << 8) | static_cast<uint64_t>(chunk[254])) & 0x3ff));

  return data_len;
}

#if defined(__AVX2__)

uint32_t branchComputeCPU_avx2(RC4_KEY key, unsigned char *sData)
{
  uint64_t lhash = hash_64_fnv1a_256(sData);
  uint64_t prev_lhash = lhash;

  unsigned char *prev_chunk;
  unsigned char *chunk;

  uint64_t tries = 0;

  while (true)
  {
    tries++;
    uint64_t random_switcher = prev_lhash ^ lhash ^ tries;

    unsigned char op = static_cast<unsigned char>(random_switcher);

    unsigned char pos1 = static_cast<unsigned char>(random_switcher >> 8);
    unsigned char pos2 = static_cast<unsigned char>(random_switcher >> 16);

    if (pos1 > pos2)
    {
      std::swap(pos1, pos2);
    }

    if (pos2 - pos1 > 32)
    {
      pos2 = pos1 + ((pos2 - pos1) & 0x1f);
    }

    chunk = &sData[(tries - 1) * 256];

    if (tries == 1) {
      prev_chunk = chunk;
    } else {
      prev_chunk = &sData[(tries - 2) * 256];

      __builtin_prefetch(prev_chunk,0,3);
      __builtin_prefetch(prev_chunk+64,0,3);
      __builtin_prefetch(prev_chunk+128,0,3);
      __builtin_prefetch(prev_chunk+192,0,3);

      // Calculate the start and end blocks
      int start_block = 0;
      int end_block = pos1 / 16;

      // Copy the blocks before pos1
      for (int i = start_block; i < end_block; i++) {
          __m128i prev_data = _mm_loadu_si128((__m128i*)&prev_chunk[i * 16]);
          _mm_storeu_si128((__m128i*)&chunk[i * 16], prev_data);
      }

      // Copy the remaining bytes before pos1
      for (int i = end_block * 16; i < pos1; i++) {
          chunk[i] = prev_chunk[i];
      }

      // Calculate the start and end blocks
      start_block = (pos2 + 15) / 16;
      end_block = 16;

      // Copy the blocks after pos2
      for (int i = start_block; i < end_block; i++) {
          __m128i prev_data = _mm_loadu_si128((__m128i*)&prev_chunk[i * 16]);
          _mm_storeu_si128((__m128i*)&chunk[i * 16], prev_data);
      }

      // Copy the remaining bytes after pos2
      for (int i = pos2; i < start_block * 16; i++) {
        chunk[i] = prev_chunk[i];
      }
    }

    __builtin_prefetch(&chunk[pos1],1,3);

    switch(op) {
      case 0:
        // #pragma GCC unroll 16
        {
          // Load 32 bytes of prev_chunk starting from i into an AVX2 256-bit register
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          __m256i pop = popcnt256_epi8(data);
          
          data = _mm256_xor_si256(data,pop);

          // Rotate left by 5
          data = _mm256_rol_epi8(data, 5);

          // Full 16-bit multiplication
          data = _mm256_mul_epi8(data, data);
          data = _mm256_rolv_epi8(data, data);

          // Write results to workerData

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        if ((pos2-pos1)%2 == 1) {
          unsigned char t1 = chunk[pos1];
          unsigned char t2 = chunk[pos2];
          chunk[pos1] = reverse8(t2);
          chunk[pos2] = reverse8(t1);
        }
        break;
      case 1:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          __m256i shift = _mm256_and_si256(data, vec_3);
          data = _mm256_sllv_epi8(data, shift);
          data = _mm256_rol_epi8(data,1);
          data = _mm256_and_si256(data, _mm256_set1_epi8(prev_chunk[pos2]));
          data = _mm256_add_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 2:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          __m256i pop = popcnt256_epi8(data);
          data = _mm256_xor_si256(data,pop);
          data = _mm256_reverse_epi8(data);

          __m256i shift = _mm256_and_si256(data, vec_3);
          data = _mm256_sllv_epi8(data, shift);

          pop = popcnt256_epi8(data);
          data = _mm256_xor_si256(data,pop);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 3:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_rolv_epi8(data,_mm256_add_epi8(data,vec_3));
          data = _mm256_xor_si256(data,_mm256_set1_epi8(chunk[pos2]));
          data = _mm256_rol_epi8(data,1);
          
          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 4:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
          data = _mm256_srlv_epi8(data,_mm256_and_si256(data,vec_3));
          data = _mm256_rolv_epi8(data,data);
          data = _mm256_sub_epi8(data,_mm256_xor_si256(data,_mm256_set1_epi8(97)));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 5:
        {
          // Load 32 bytes of prev_chunk starting from i into an AVX2 256-bit register
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          __m256i pop = popcnt256_epi8(data);
          data = _mm256_xor_si256(data,pop);
          data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
          data = _mm256_sllv_epi8(data,_mm256_and_si256(data,vec_3));
          data = _mm256_srlv_epi8(data,_mm256_and_si256(data,vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        
        break;
      case 6:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_sllv_epi8(data,_mm256_and_si256(data,vec_3));
          data = _mm256_rol_epi8(data, 3);
          data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));

          __m256i x = _mm256_xor_si256(data,_mm256_set1_epi8(97));
          data = _mm256_sub_epi8(data,x);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 7:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_add_epi8(data, data);;
          data = _mm256_rolv_epi8(data, data);

          __m256i pop = popcnt256_epi8(data);
          data = _mm256_xor_si256(data,pop);
          data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 8:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
          data = _mm256_rol_epi8(data,2);
          data = _mm256_sllv_epi8(data,_mm256_and_si256(data,vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 9:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
          data = _mm256_xor_si256(data, _mm256_rol_epi8(data,4));
          data = _mm256_srlv_epi8(data, _mm256_and_si256(data,vec_3));
          data = _mm256_xor_si256(data, _mm256_rol_epi8(data,2));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 10:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
          data = _mm256_mul_epi8(data, data);
          data = _mm256_rol_epi8(data, 3);
          data = _mm256_mul_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 11:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_rol_epi8(data, 6);
          data = _mm256_and_si256(data,_mm256_set1_epi8(chunk[pos2]));
          data = _mm256_rolv_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 12:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_xor_si256(data, _mm256_rol_epi8(data,2));
          data = _mm256_mul_epi8(data, data);
          data = _mm256_xor_si256(data, _mm256_rol_epi8(data,2));
          data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 13:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_rol_epi8(data, 1);
          data = _mm256_xor_si256(data,_mm256_set1_epi8(chunk[pos2]));
          data = _mm256_srlv_epi8(data,_mm256_and_si256(data,vec_3));
          data = _mm256_rol_epi8(data, 5);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 14:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_srlv_epi8(data,_mm256_and_si256(data,vec_3));
          data = _mm256_sllv_epi8(data,_mm256_and_si256(data,vec_3));
          data = _mm256_mul_epi8(data, data);
          data = _mm256_sllv_epi8(data,_mm256_and_si256(data,vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 15:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_xor_si256(data, _mm256_rol_epi8(data,2));
          data = _mm256_sllv_epi8(data,_mm256_and_si256(data,vec_3));
          data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
          data = _mm256_sub_epi8(data,_mm256_xor_si256(data,_mm256_set1_epi8(97)));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 16:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_xor_si256(data, _mm256_rol_epi8(data,4));
          data = _mm256_mul_epi8(data, data);
          data = _mm256_rol_epi8(data,1);
          data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 17:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
          data = _mm256_mul_epi8(data, data);
          data = _mm256_rol_epi8(data,5);
          data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 18:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
          data = _mm256_rol_epi8(data, 1);
          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 19:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_sub_epi8(data,_mm256_xor_si256(data,_mm256_set1_epi8(97)));
          data = _mm256_rol_epi8(data, 5);
          data = _mm256_sllv_epi8(data,_mm256_and_si256(data,vec_3));
          data = _mm256_add_epi8(data, data);;;

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 20:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
          data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
          data = _mm256_reverse_epi8(data);
          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 21:

        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_rol_epi8(data, 1);
          data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
          data = _mm256_add_epi8(data, data);
          data = _mm256_and_si256(data,_mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
    break;
      case 22:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_sllv_epi8(data, _mm256_and_si256(data,vec_3));
          data = _mm256_reverse_epi8(data);
          data = _mm256_mul_epi8(data,data);
          data = _mm256_rol_epi8(data,1);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 23:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_rol_epi8(data, 4);
          data = _mm256_xor_si256(data,popcnt256_epi8(data));
          data = _mm256_and_si256(data,_mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
      break;
      case 24:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_add_epi8(data, data);
          data = _mm256_srlv_epi8(data, _mm256_and_si256(data,vec_3));
          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
          data = _mm256_rol_epi8(data, 5);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 25:
  #pragma GCC unroll 32
        for (int i = pos1; i < pos2; i++)
        {
          // INSERT_RANDOM_CODE_START
          chunk[i] = prev_chunk[i] ^ (unsigned char)bitTable[prev_chunk[i]];             // ones count bits
          chunk[i] = rl8(chunk[i], 3);                // rotate  bits by 3
          chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
          chunk[i] -= (chunk[i] ^ 97);                      // XOR and -
                                                                            // INSERT_RANDOM_CODE_END
        }
        break;
      case 26:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_mul_epi8(data, data);
          data = _mm256_xor_si256(data,popcnt256_epi8(data));
          data = _mm256_add_epi8(data, data);
          data = _mm256_reverse_epi8(data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 27:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_rol_epi8(data, 5);
          data = _mm256_and_si256(data,_mm256_set1_epi8(chunk[pos2]));
          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
          data = _mm256_rol_epi8(data, 5);
          
          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 28:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_sllv_epi8(data, _mm256_and_si256(data,vec_3));
          data = _mm256_add_epi8(data, data);
          data = _mm256_add_epi8(data, data);
          data = _mm256_rol_epi8(data, 5);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 29:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_mul_epi8(data, data);
          data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
          data = _mm256_srlv_epi8(data, _mm256_and_si256(data,vec_3));
          data = _mm256_add_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 30:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
          data = _mm256_rol_epi8(data, 5);
          data = _mm256_sllv_epi8(data, _mm256_and_si256(data,vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 31:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;
        
          data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
          data = _mm256_sllv_epi8(data, _mm256_and_si256(data,vec_3));
          data = _mm256_mul_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 32:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
          data = _mm256_reverse_epi8(data);
          data = _mm256_rol_epi8(data, 3);
          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 33:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_rolv_epi8(data, data);
          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
          data = _mm256_reverse_epi8(data);
          data = _mm256_mul_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 34:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
          data = _mm256_sllv_epi8(data, _mm256_and_si256(data,vec_3));
          data = _mm256_sllv_epi8(data, _mm256_and_si256(data,vec_3));
          data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 35:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_add_epi8(data, data);
          data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
          data = _mm256_rol_epi8(data, 1);
          data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 36:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_xor_si256(data, popcnt256_epi8(data));
          data = _mm256_rol_epi8(data, 1);
          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
          data = _mm256_rol_epi8(data, 1);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 37:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_rolv_epi8(data, data);
          data = _mm256_srlv_epi8(data, _mm256_and_si256(data,vec_3));
          data = _mm256_srlv_epi8(data, _mm256_and_si256(data,vec_3));
          data = _mm256_mul_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 38:
  #pragma GCC unroll 32
        for (int i = pos1; i < pos2; i++)
        {
          // INSERT_RANDOM_CODE_START
          chunk[i] = prev_chunk[i] >> (prev_chunk[i] & 3);    // shift right
          chunk[i] = rl8(chunk[i], 3);                // rotate  bits by 3
          chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
          chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
                                                                            // INSERT_RANDOM_CODE_END
        }
        break;
      case 39:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
          data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
          data = _mm256_srlv_epi8(data, _mm256_and_si256(data,vec_3));
          data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 40:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_rolv_epi8(data, data);
          data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
          data = _mm256_xor_si256(data, popcnt256_epi8(data));
          data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 41:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_rol_epi8(data, 5);
          data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
          data = _mm256_rol_epi8(data, 3);
          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 42:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_rol_epi8(data, 4);
          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
          data = _mm256_rolv_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 43:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
          data = _mm256_add_epi8(data, data);
          data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
          data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 44:
  #pragma GCC unroll 32
        for (int i = pos1; i < pos2; i++)
        {
          // INSERT_RANDOM_CODE_START
          chunk[i] = prev_chunk[i] ^ (unsigned char)bitTable[prev_chunk[i]];             // ones count bits
          chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
          chunk[i] = rl8(chunk[i], 3);                // rotate  bits by 3
          chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
                                                                            // INSERT_RANDOM_CODE_END
        }
        break;
      case 45:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;
        
          data = _mm256_rol_epi8(data, 2);
          data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
          data = _mm256_xor_si256(data, popcnt256_epi8(data));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 46:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;
        
          data = _mm256_xor_si256(data, popcnt256_epi8(data));
          data = _mm256_add_epi8(data, data);
          data = _mm256_rol_epi8(data, 5);
          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 47:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_rol_epi8(data, 5);
          data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
          data = _mm256_rol_epi8(data, 5);
          data = _mm256_sllv_epi8(data, _mm256_and_si256(data,vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 48:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_rolv_epi8(data, data);
          data = _mm256_rol_epi8(data, 5);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 49:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;
        
          data = _mm256_xor_si256(data, popcnt256_epi8(data));
          data = _mm256_add_epi8(data, data);
          data = _mm256_reverse_epi8(data);
          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 50:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;
        
          data = _mm256_reverse_epi8(data);
          data = _mm256_rol_epi8(data, 3);
          data = _mm256_add_epi8(data, data);
          data = _mm256_rol_epi8(data, 1);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 51:
  #pragma GCC unroll 32
        for (int i = pos1; i < pos2; i++)
        {
          // INSERT_RANDOM_CODE_START
          chunk[i] = prev_chunk[i] ^ chunk[pos2];     // XOR
          chunk[i] ^= rl8(chunk[i], 4); // rotate  bits by 4
          chunk[i] ^= rl8(chunk[i], 4); // rotate  bits by 4
          chunk[i] = rl8(chunk[i], 5);  // rotate  bits by 5
                                                              // INSERT_RANDOM_CODE_END
        }
        break;
      case 52:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_rolv_epi8(data, data);
          data = _mm256_srlv_epi8(data, _mm256_and_si256(data,vec_3));
          data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
          data = _mm256_xor_si256(data, popcnt256_epi8(data));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 53:
  #pragma GCC unroll 32
        for (int i = pos1; i < pos2; i++)
        {
          // INSERT_RANDOM_CODE_START
          chunk[i] = prev_chunk[i]*2;                 // +
          chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
          chunk[i] ^= rl8(chunk[i], 4);   // rotate  bits by 4
          chunk[i] ^= rl8(chunk[i], 4);   // rotate  bits by 4
                                                                // INSERT_RANDOM_CODE_END
        }
        break;
      case 54:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;
        
          data = _mm256_reverse_epi8(data);
          data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }

        break;
      case 55:
  #pragma GCC unroll 32
        for (int i = pos1; i < pos2; i++)
        {
          // INSERT_RANDOM_CODE_START
          chunk[i] = reverse8(prev_chunk[i]);      // reverse bits
          chunk[i] ^= rl8(chunk[i], 4); // rotate  bits by 4
          chunk[i] ^= rl8(chunk[i], 4); // rotate  bits by 4
          chunk[i] = rl8(chunk[i], 1);  // rotate  bits by 1
                                                              // INSERT_RANDOM_CODE_END
        }
        break;
      case 56:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
          data = _mm256_mul_epi8(data, data);
          data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
          data = _mm256_rol_epi8(data, 1);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 57:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_rolv_epi8(data, data);
          data = _mm256_reverse_epi8(data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 58:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;
        
          data = _mm256_reverse_epi8(data);
          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
          data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
          data = _mm256_add_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }  
        break;
      case 59:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_rol_epi8(data, 1);
          data = _mm256_mul_epi8(data, data);
          data = _mm256_rolv_epi8(data, data);
          data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 60:
        {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_mul_epi8(data, data);
            data = _mm256_rol_epi8(data, 3);

            #ifdef _WIN32
              data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            #else
              data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            #endif
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }

        break;
      case 61:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_rol_epi8(data, 5);
          data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 62:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
          data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
          data = _mm256_add_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 63:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_rol_epi8(data, 5);
          data = _mm256_xor_si256(data, popcnt256_epi8(data));
          data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
          data = _mm256_add_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }

        break;
      case 64:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
          data = _mm256_reverse_epi8(data);
          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
          data = _mm256_mul_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 65:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;


          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
          data = _mm256_mul_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 66:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
          data = _mm256_reverse_epi8(data);
          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
          data = _mm256_rol_epi8(data, 1);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 67:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_rol_epi8(data, 1);
          data = _mm256_xor_si256(data, popcnt256_epi8(data));
          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
          data = _mm256_rol_epi8(data, 5);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 68:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
          data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
          data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 69:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_add_epi8(data, data);
          data = _mm256_mul_epi8(data, data);
          data = _mm256_reverse_epi8(data);
          data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 70:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
          data = _mm256_mul_epi8(data, data);
          data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 71:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_rol_epi8(data, 5);
          data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
          data = _mm256_mul_epi8(data, data);
          data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 72:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_reverse_epi8(data);
          data = _mm256_xor_si256(data, popcnt256_epi8(data));
          data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
          data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 73:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_xor_si256(data, popcnt256_epi8(data));
          data = _mm256_reverse_epi8(data);
          data = _mm256_rol_epi8(data, 5);
          data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 74:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_mul_epi8(data, data);
          data = _mm256_rol_epi8(data, 3);
          data = _mm256_reverse_epi8(data);
          data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
      case 75:
        {
          __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
          __m256i old = data;

          data = _mm256_mul_epi8(data, data);
          data = _mm256_xor_si256(data, popcnt256_epi8(data));
          data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
          data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
          _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
        }
        break;
        case 76:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rolv_epi8(data, data);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_rol_epi8(data, 5);
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 77:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 3);
            data = _mm256_add_epi8(data, data);
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_xor_si256(data, popcnt256_epi8(data));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 78:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rolv_epi8(data, data);
            data = _mm256_reverse_epi8(data);
            data = _mm256_mul_epi8(data, data);
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 79:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_add_epi8(data, data);
            data = _mm256_mul_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 80:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rolv_epi8(data, data);
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_add_epi8(data, data);
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 81:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_rolv_epi8(data, data);
            data = _mm256_xor_si256(data, popcnt256_epi8(data));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 82:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 83:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_reverse_epi8(data);
            data = _mm256_rol_epi8(data, 3);
            data = _mm256_reverse_epi8(data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 84:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            data = _mm256_rol_epi8(data, 1);
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_add_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 85:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_rolv_epi8(data, data);
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 86:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_rolv_epi8(data, data);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 87:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_add_epi8(data, data);
            data = _mm256_rol_epi8(data, 3);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_add_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 88:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_rol_epi8(data, 1);
            data = _mm256_mul_epi8(data, data);
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 89:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_add_epi8(data, data);
            data = _mm256_mul_epi8(data, data);
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 90:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_reverse_epi8(data);
            data = _mm256_rol_epi8(data, 6);
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 91:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, popcnt256_epi8(data));
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_reverse_epi8(data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 92:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, popcnt256_epi8(data));
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_xor_si256(data, popcnt256_epi8(data));
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 93:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_mul_epi8(data, data);
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_add_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 94:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 1);
            data = _mm256_rolv_epi8(data, data);
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 95:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 1);
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_rol_epi8(data, 2);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 96:
    #pragma GCC unroll 32
          for (int i = pos1; i < pos2; i++)
          {
            // INSERT_RANDOM_CODE_START
            chunk[i] = prev_chunk[i] ^ rl8(prev_chunk[i], 2);   // rotate  bits by 2
            chunk[i] ^= rl8(chunk[i], 2);   // rotate  bits by 2
            chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
            chunk[i] = rl8(chunk[i], 1);    // rotate  bits by 1
                                                                  // INSERT_RANDOM_CODE_END
          }
          break;
        case 97:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 1);
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_xor_si256(data, popcnt256_epi8(data));
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 98:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 99:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            data = _mm256_reverse_epi8(data);
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 100:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rolv_epi8(data, data);
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_reverse_epi8(data);
            data = _mm256_xor_si256(data, popcnt256_epi8(data));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 101:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_xor_si256(data, popcnt256_epi8(data));
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 102:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 3);
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            data = _mm256_add_epi8(data, data);
            data = _mm256_rol_epi8(data, 3);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 103:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 1);
            data = _mm256_reverse_epi8(data);
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_rolv_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 104:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_reverse_epi8(data);
            data = _mm256_xor_si256(data, popcnt256_epi8(data));
            data = _mm256_rol_epi8(data, 5);
            data = _mm256_add_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 105:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_rol_epi8(data, 3);
            data = _mm256_rolv_epi8(data, data);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 106:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_reverse_epi8(data);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_rol_epi8(data, 1);
            data = _mm256_mul_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 107:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_rol_epi8(data, 6);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 108:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 109:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_mul_epi8(data, data);
            data = _mm256_rolv_epi8(data, data);
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 110:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_add_epi8(data, data);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 111:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_mul_epi8(data, data);
            data = _mm256_reverse_epi8(data);
            data = _mm256_mul_epi8(data, data);
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 112:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 3);
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_rol_epi8(data, 5);
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 113:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 6);
            data = _mm256_xor_si256(data, popcnt256_epi8(data));
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 114:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 1);
            data = _mm256_reverse_epi8(data);
            data = _mm256_rolv_epi8(data, data);
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 115:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rolv_epi8(data, data);
            data = _mm256_rol_epi8(data, 5);
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_rol_epi8(data, 3);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 116:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_xor_si256(data, popcnt256_epi8(data));
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 117:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_rol_epi8(data, 3);
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 118:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_add_epi8(data, data);
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_rol_epi8(data, 5);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 119:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_reverse_epi8(data);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 120:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_mul_epi8(data, data);
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_reverse_epi8(data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 121:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_add_epi8(data, data);
            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);
            data = _mm256_mul_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 122:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_rolv_epi8(data, data);
            data = _mm256_rol_epi8(data, 5);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 123:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_rol_epi8(data, 6);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 124:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 125:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_reverse_epi8(data);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_add_epi8(data, data);
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 126:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 1);
            data = _mm256_reverse_epi8(data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 127:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_mul_epi8(data, data);
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 128:
    #pragma GCC unroll 32
          for (int i = pos1; i < pos2; i++)
          {
            // INSERT_RANDOM_CODE_START
            chunk[i] = rl8(prev_chunk[i], prev_chunk[i]); // rotate  bits by random
            chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
            chunk[i] ^= rl8(chunk[i], 2);               // rotate  bits by 2
            chunk[i] = rl8(chunk[i], 5);                // rotate  bits by 5
                                                                              // INSERT_RANDOM_CODE_END
          }
          break;
        case 129:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);
            pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 130:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_rolv_epi8(data, data);
            data = _mm256_rol_epi8(data, 1);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 131:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            data = _mm256_rol_epi8(data, 1);
            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);
            data = _mm256_mul_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 132:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_reverse_epi8(data);
            data = _mm256_rol_epi8(data, 5);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 133:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_rol_epi8(data, 5);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 134:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_rol_epi8(data, 1);
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 135:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_add_epi8(data, data);
            data = _mm256_reverse_epi8(data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 136:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_rol_epi8(data, 5);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 137:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 5);
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_reverse_epi8(data);
            data = _mm256_rolv_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 138:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_add_epi8(data, data);
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 139:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_rol_epi8(data, 3);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 140:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 1);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_rol_epi8(data, 5);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 141:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 1);
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);
            data = _mm256_add_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 142:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_rol_epi8(data, 5);
            data = _mm256_reverse_epi8(data);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 143:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_rol_epi8(data, 3);
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 144:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rolv_epi8(data, data);
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_rolv_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 145:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_reverse_epi8(data);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 146:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 147:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_mul_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 148:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_rol_epi8(data, 5);
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 149:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_reverse_epi8(data);
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            data = _mm256_add_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 150:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 151:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_add_epi8(data, data);
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_mul_epi8(data, data);
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 152:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 153:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 4);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 154:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 5);
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 155:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 156:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_rol_epi8(data, 4);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 157:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_rolv_epi8(data, data);
            data = _mm256_rol_epi8(data, 1);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 158:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);
            data = _mm256_rol_epi8(data, 3);
            data = _mm256_add_epi8(data, data);
            data = _mm256_rol_epi8(data, 1);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 159:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_rolv_epi8(data, data);
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 160:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_reverse_epi8(data);
            data = _mm256_rol_epi8(data, 4);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 161:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_rol_epi8(data, 5);
            data = _mm256_rolv_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 162:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_mul_epi8(data, data);
            data = _mm256_reverse_epi8(data);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 163:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_rol_epi8(data, 1);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 164:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_mul_epi8(data, data);
            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 165:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_add_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 166:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 3);
            data = _mm256_add_epi8(data, data);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 167:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_mul_epi8(data, data);
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 168:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rolv_epi8(data, data);
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_rolv_epi8(data, data);
            data = _mm256_rol_epi8(data, 1);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 169:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 1);
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 170:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            data = _mm256_reverse_epi8(data);
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            data = _mm256_mul_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 171:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 3);
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);
            data = _mm256_reverse_epi8(data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 172:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_rol_epi8(data, 1);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 173:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_mul_epi8(data, data);
            data = _mm256_add_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 174:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_rolv_epi8(data, data);
            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);
            pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 175:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 3);
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            data = _mm256_mul_epi8(data, data);
            data = _mm256_rol_epi8(data, 5);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 176:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_mul_epi8(data, data);
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_rol_epi8(data, 5);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 177:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 178:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_add_epi8(data, data);
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_rol_epi8(data, 1);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 179:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_add_epi8(data, data);
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_reverse_epi8(data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 180:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 181:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_rol_epi8(data, 5);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 182:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_rol_epi8(data, 6);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 183:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_add_epi8(data, data);
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            data = _mm256_mul_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 184:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_mul_epi8(data, data);
            data = _mm256_rol_epi8(data, 5);
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 185:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_rol_epi8(data, 5);
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 186:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 187:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_add_epi8(data, data);
            data = _mm256_rol_epi8(data, 3);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 188:
    #pragma GCC unroll 32
          for (int i = pos1; i < pos2; i++)
          {
            // INSERT_RANDOM_CODE_START
            chunk[i] ^= rl8(prev_chunk[i], 4);   // rotate  bits by 4
            chunk[i] ^= (unsigned char)bitTable[chunk[i]]; // ones count bits
            chunk[i] ^= rl8(chunk[i], 4);   // rotate  bits by 4
            chunk[i] ^= rl8(chunk[i], 4);   // rotate  bits by 4
                                                                  // INSERT_RANDOM_CODE_END
          }
          break;
        case 189:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 5);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 190:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 5);
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 191:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_add_epi8(data, data);
            data = _mm256_rol_epi8(data, 3);
            data = _mm256_rolv_epi8(data, data);
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 192:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_add_epi8(data, data);
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_add_epi8(data, data);
            data = _mm256_mul_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 193:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_rolv_epi8(data, data);
            data = _mm256_rol_epi8(data, 1);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 194:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_rolv_epi8(data, data);
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 195:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 196:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 3);
            data = _mm256_reverse_epi8(data);
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_rol_epi8(data, 1);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 197:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_rolv_epi8(data, data);
            data = _mm256_mul_epi8(data, data);
            data = _mm256_mul_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 198:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_reverse_epi8(data);
            data = _mm256_rol_epi8(data, 1);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 199:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_add_epi8(data, data);
            data = _mm256_mul_epi8(data, data);
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 200:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);
            data = _mm256_reverse_epi8(data);
            data = _mm256_reverse_epi8(data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 201:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 3);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 202:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_rolv_epi8(data, data);
            data = _mm256_rol_epi8(data, 5);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 203:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_rol_epi8(data, 1);
            data = _mm256_rolv_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 204:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 5);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_rolv_epi8(data, data);
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 205:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_add_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 206:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_reverse_epi8(data);
            data = _mm256_reverse_epi8(data);
            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 207:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);
            pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 208:
    #pragma GCC unroll 32
          for (int i = pos1; i < pos2; i++)
          {
            // INSERT_RANDOM_CODE_START
            chunk[i] = prev_chunk[i]*2;                          // +
            chunk[i] += chunk[i];                          // +
            chunk[i] = chunk[i] >> (chunk[i] & 3); // shift right
            chunk[i] = rl8(chunk[i], 3);             // rotate  bits by 3
                                                                          // INSERT_RANDOM_CODE_END
          }
          break;
        case 209:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 5);
            data = _mm256_reverse_epi8(data);
            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 210:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_rolv_epi8(data, data);
            data = _mm256_rol_epi8(data, 5);
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 211:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_add_epi8(data, data);
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            data = _mm256_rolv_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 212:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rolv_epi8(data, data);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            // data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            // data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 213:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_add_epi8(data, data);
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_rol_epi8(data, 3);
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 214:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 215:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_mul_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 216:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rolv_epi8(data, data);
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 217:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 5);
            data = _mm256_add_epi8(data, data);
            data = _mm256_rol_epi8(data, 1);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 218:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_reverse_epi8(data);
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_mul_epi8(data, data);
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 219:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_rol_epi8(data, 3);
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_reverse_epi8(data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 220:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 1);
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_reverse_epi8(data);
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 221:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 5);
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_reverse_epi8(data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 222:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_mul_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 223:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 3);
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_rolv_epi8(data, data);
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 224:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_rol_epi8(data, 4);
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 225:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_reverse_epi8(data);
            data = _mm256_rol_epi8(data, 3);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 226:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_reverse_epi8(data);
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            data = _mm256_mul_epi8(data, data);
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 227:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 228:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_add_epi8(data, data);
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_add_epi8(data, data);
            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 229:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 3);
            data = _mm256_rolv_epi8(data, data);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 230:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_mul_epi8(data, data);
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_rolv_epi8(data, data);
            data = _mm256_rolv_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 231:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 3);
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_reverse_epi8(data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 232:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_mul_epi8(data, data);
            data = _mm256_mul_epi8(data, data);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_rol_epi8(data, 5);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 233:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 1);
            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);
            data = _mm256_rol_epi8(data, 3);
            pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 234:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_mul_epi8(data, data);
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 235:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_mul_epi8(data, data);
            data = _mm256_rol_epi8(data, 3);
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 236:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_add_epi8(data, data);
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 237:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 5);
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_rol_epi8(data, 3);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 238:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_add_epi8(data, data);
            data = _mm256_add_epi8(data, data);
            data = _mm256_rol_epi8(data, 3);
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 239:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 6);
            data = _mm256_mul_epi8(data, data);
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 240:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_add_epi8(data, data);
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 241:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_rol_epi8(data, 1);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 242:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_add_epi8(data, data);
            data = _mm256_add_epi8(data, data);
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 243:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 5);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);
            data = _mm256_rol_epi8(data, 1);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 244:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_reverse_epi8(data);
            data = _mm256_rol_epi8(data, 5);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 245:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            data = _mm256_rol_epi8(data, 5);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 246:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_add_epi8(data, data);
            data = _mm256_rol_epi8(data, 1);
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            data = _mm256_add_epi8(data, data);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 247:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_rol_epi8(data, 5);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_rol_epi8(data, 5);
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 248:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);
            data = _mm256_rol_epi8(data, 5);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 249:
    #pragma GCC unroll 32
          for (int i = pos1; i < pos2; i++)
          {
            // INSERT_RANDOM_CODE_START
            chunk[i] = reverse8(prev_chunk[i]);                    // reverse bits
            chunk[i] ^= rl8(chunk[i], 4);               // rotate  bits by 4
            chunk[i] ^= rl8(chunk[i], 4);               // rotate  bits by 4
            chunk[i] = rl8(chunk[i], chunk[i]); // rotate  bits by random
                                                                              // INSERT_RANDOM_CODE_END
          }
          break;
        case 250:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            data = _mm256_rolv_epi8(data, data);
            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 251:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_add_epi8(data, data);
            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);
            data = _mm256_reverse_epi8(data);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 252:
          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            data = _mm256_reverse_epi8(data);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        case 253:
          {
            std::copy(&prev_chunk[pos1], &prev_chunk[pos2], &chunk[pos1]);
    #pragma GCC unroll 32
            for (int i = pos1; i < pos2; i++)
            {
              // INSERT_RANDOM_CODE_START
              chunk[i] = rl8(chunk[i], 3);  // rotate  bits by 3
              chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
              chunk[i] ^= chunk[pos2];     // XOR
              chunk[i] = rl8(chunk[i], 3);  // rotate  bits by 3
              // INSERT_RANDOM_CODE_END

              prev_lhash = lhash + prev_lhash;
              lhash = XXHash64::hash(chunk, pos2,0);
            }
            break;
          }
        case 254:
        case 255:
          RC4_set_key(&key, 256, prev_chunk);

          {
            __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
            __m256i old = data;

            __m256i pop = popcnt256_epi8(data);
            data = _mm256_xor_si256(data, pop);
            data = _mm256_rol_epi8(data, 3);
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            data = _mm256_rol_epi8(data, 3);

          data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
            _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
          }
          break;
        default:
          break;
      }

    __builtin_prefetch(chunk,0,3);
    // __builtin_prefetch(chunk+64,0,3);
    // __builtin_prefetch(chunk+128,0,3);
    __builtin_prefetch(chunk+192,0,3);

    unsigned char A = (chunk[pos1] - chunk[pos2]);
    A = (256 + (A % 256)) % 256;

    if (A < 0x10)
    { // 6.25 % probability
      prev_lhash = lhash + prev_lhash;
      lhash = XXHash64::hash(chunk, pos2, 0);
    }

    if (A < 0x20)
    { // 12.5 % probability
      prev_lhash = lhash + prev_lhash;
      lhash = hash_64_fnv1a(chunk, pos2);
    }

    if (A < 0x30)
    { // 18.75 % probability
      prev_lhash = lhash + prev_lhash;
      HH_ALIGNAS(16)
      const highwayhash::HH_U64 key2[2] = {tries, prev_lhash};
      lhash = highwayhash::SipHash(key2, (char*)chunk, pos2); // more deviations
    }

    if (A <= 0x40)
    { // 25% probablility
      RC4(&key, 256, chunk, chunk);
    }

    chunk[255] = chunk[255] ^ chunk[pos1] ^ chunk[pos2];

    if (tries > 260 + 16 || (sData[(tries-1)*256+255] >= 0xf0 && tries > 260))
    {
      break;
    }
  }
  uint32_t data_len = static_cast<uint32_t>((tries - 4) * 256 + (((static_cast<uint64_t>(chunk[253]) << 8) | static_cast<uint64_t>(chunk[254])) & 0x3ff));

  return data_len;
}

#endif

// WOLF CODE

uint32_t wolfCompute(RC4_KEY key, unsigned char *sData)
{
  uint64_t lhash = hash_64_fnv1a_256(sData);
  uint64_t prev_lhash = lhash;

  unsigned char *prev_chunk;
  unsigned char *chunk;

  uint64_t tries = 0;

  unsigned char pos1;
  unsigned char pos2;

  while (true)
  {
    tries++;
    uint64_t random_switcher = prev_lhash ^ lhash ^ tries;

    unsigned char op = static_cast<unsigned char>(random_switcher);

    unsigned char p1 = static_cast<unsigned char>(random_switcher >> 8);
    unsigned char p2 = static_cast<unsigned char>(random_switcher >> 16);

    if (p1 > p2)
    {
      std::swap(p1, p2);
    }

    if (p2 - p1 > 32)
    {
      p2 = p1 + ((p2 - p1) & 0x1f);
    }

    pos1 = p1;
    pos2 = p2;

    chunk = &sData[(tries - 1) * 256];

    if (tries == 1) {
      prev_chunk = chunk;
    } else {
      prev_chunk = &sData[(tries - 2) * 256];

      #if defined(__AVX2__)
        __builtin_prefetch(prev_chunk,0,3);
        __builtin_prefetch(prev_chunk+64,0,3);
        __builtin_prefetch(prev_chunk+128,0,3);
        __builtin_prefetch(prev_chunk+192,0,3);

        // Calculate the start and end blocks
        int start_block = 0;
        int end_block = pos1 / 16;

        // Copy the blocks before pos1
        for (int i = start_block; i < end_block; i++) {
            __m128i prev_data = _mm_loadu_si128((__m128i*)&prev_chunk[i * 16]);
            _mm_storeu_si128((__m128i*)&chunk[i * 16], prev_data);
        }

        // Copy the remaining bytes before pos1
        for (int i = end_block * 16; i < pos1; i++) {
            chunk[i] = prev_chunk[i];
        }

        // Calculate the start and end blocks
        start_block = (pos2 + 15) / 16;
        end_block = 16;

        // Copy the blocks after pos2
        for (int i = start_block; i < end_block; i++) {
            __m128i prev_data = _mm_loadu_si128((__m128i*)&prev_chunk[i * 16]);
            _mm_storeu_si128((__m128i*)&chunk[i * 16], prev_data);
        }

        // Copy the remaining bytes after pos2
        for (int i = pos2; i < start_block * 16; i++) {
          chunk[i] = prev_chunk[i];
        }
      #endif
    }

    #if defined(__AVX2__)
        __builtin_prefetch(&chunk[pos1],1,3);
    #else
        memcpy(chunk, prev_chunk, 256);
    #endif

    uint32_t Opcode = CodeLUT[op];

    if (op >= 254) {
      RC4_set_key(&key, 256,  prev_chunk);
    }
        
    #if defined(__AVX2__)
        __m256i data = _mm256_loadu_si256((__m256i*)&prev_chunk[pos1]);
        __m256i old = data;

        for (int j = 3; j >= 0; --j)
        {
          uint8_t insn = (Opcode >> (j << 3)) & 0xFF;
          switch (insn)
          {
          case 0:
            data = _mm256_add_epi8(data, data);
            break;
          case 1:
            data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97)));
            break;
          case 2:
            data = _mm256_mul_epi8(data, data);
            break;
          case 3:
            data = _mm256_xor_si256(data, _mm256_set1_epi8(chunk[pos2]));
            break;
          case 4:
            data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL));
            break;
          case 5:
            data = _mm256_and_si256(data, _mm256_set1_epi8(chunk[pos2]));
            break;
          case 6:
            data = _mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3));
            break;
          case 7:
            data = _mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3));
            break;
          case 8:
            data = _mm256_reverse_epi8(data);
            break;
          case 9:
            data = _mm256_xor_si256(data, popcnt256_epi8(data));
            break;
          case 10:
            data = _mm256_rolv_epi8(data, data);
            break;
          case 11:
            data = _mm256_rol_epi8(data, 1);
            break;
          case 12:
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 2));
            break;
          case 13:
            data = _mm256_rol_epi8(data, 3);
            break;
          case 14:
            data = _mm256_xor_si256(data, _mm256_rol_epi8(data, 4));
            break;
          case 15:
            data = _mm256_rol_epi8(data, 5);
            break;
          }
        }
    
        data = _mm256_blendv_epi8(old, data, genMask(pos2-pos1));
        _mm256_storeu_si256((__m256i*)&chunk[pos1], data);
     #else
#pragma GCC unroll 32
        for(int i = pos1; i < pos2; ++i)
        {
            for (int j = 3; j >= 0; --j)
            {
              uint8_t insn = (Opcode >> (j << 3)) & 0xFF;
              switch (insn)
              {
              case 0:
                chunk[i] += chunk[i];
                break;
              case 1:
                chunk[i] -= (chunk[i] ^ 97);
                break;
              case 2:
                chunk[i] *= chunk[i];
                break;
              case 3:
                chunk[i] ^= chunk[pos2];
                break;
              case 4:
                chunk[i] = ~chunk[i];
                break;
              case 5:
                chunk[i] = chunk[i] & chunk[pos2];
                break;
              case 6:
                chunk[i] = chunk[i] << (chunk[i] & 3);
                break;
              case 7:
                chunk[i] = chunk[i] >> (chunk[i] & 3);
                break;
              case 8:
                chunk[i] = reverse8(chunk[i]);
                break;
              case 9:
                chunk[i] ^= (unsigned char)bitTable[chunk[i]];
                break;
              case 10:
                chunk[i] = rl8(chunk[i], chunk[i]);
                break;
              case 11:
                chunk[i] = rl8(chunk[i], 1);
                break;
              case 12:
                chunk[i] ^= rl8(chunk[i], 2);
                break;
              case 13:
                chunk[i] = rl8(chunk[i], 3);
                break;
              case 14:
                chunk[i] ^= rl8(chunk[i], 4);
                break;
              case 15:
                chunk[i] = rl8(chunk[i], 5);
                break;
              }
            }
        }
    #endif

    if (op == 253)
    {
        #if defined(__AVX2__)
            std::copy(&prev_chunk[pos1], &prev_chunk[pos2], &chunk[pos1]);
        #else
#pragma GCC unroll 32
            for (int i = pos1; i < pos2; i++)
            {
              chunk[i] = prev_chunk[i];
            }
        #endif
#pragma GCC unroll 32
        for (int i = pos1; i < pos2; i++)
        {

          // INSERT_RANDOM_CODE_START
          chunk[i] = rl8(chunk[i], 3);  // rotate  bits by 3
          chunk[i] ^= rl8(chunk[i], 2); // rotate  bits by 2
          chunk[i] ^= chunk[pos2];     // XOR
          chunk[i] = rl8(chunk[i], 3);  // rotate  bits by 3
          // INSERT_RANDOM_CODE_END

          prev_lhash = lhash + prev_lhash;
          lhash = XXHash64::hash(chunk, pos2,0);
        }
    }

    if (op == 0) {
      if ((pos2-pos1)%2 == 1) {
        unsigned char t1 = chunk[pos1];
        unsigned char t2 = chunk[pos2];
        chunk[pos1] = reverse8(t2);
        chunk[pos2] = reverse8(t1);
      }
    }

    #if defined(__AVX2__)
        __builtin_prefetch(chunk,0,3);
        // __builtin_prefetch(chunk+64,0,3);
        // __builtin_prefetch(chunk+128,0,3);
        __builtin_prefetch(chunk+192,0,3);
    #endif

    unsigned char A = (chunk[pos1] - chunk[pos2]);
    A = (256 + (A % 256)) % 256;

    if (A < 0x10)
    { // 6.25 % probability
      prev_lhash = lhash + prev_lhash;
      lhash = XXHash64::hash(chunk, pos2, 0);
    }

    if (A < 0x20)
    { // 12.5 % probability
      prev_lhash = lhash + prev_lhash;
      lhash = hash_64_fnv1a(chunk, pos2);
    }

    if (A < 0x30)
    { // 18.75 % probability
      prev_lhash = lhash + prev_lhash;
      HH_ALIGNAS(16)
      const highwayhash::HH_U64 key2[2] = {tries, prev_lhash};
      lhash = highwayhash::SipHash(key2, (char*)chunk, pos2); // more deviations
    }

    if (A <= 0x40)
    { // 25% probablility
      RC4(&key, 256, chunk,  chunk);
    }

    chunk[255] = chunk[255] ^ chunk[pos1] ^ chunk[pos2];

    if (tries > 260 + 16 || (sData[(tries-1)*256+255] >= 0xf0 && tries > 260))
    {
      break;
    }
  }

  uint32_t data_len = static_cast<uint32_t>((tries - 4) * 256 + (((static_cast<uint64_t>(chunk[253]) << 8) | static_cast<uint64_t>(chunk[254])) & 0x3ff));

  return data_len;
}
