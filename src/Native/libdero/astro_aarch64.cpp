
#if defined(__aarch64__)

#include "astro_aarch64.hpp"

inline uint8x16_t binary_not(uint8x16_t data) {
  //chunk[i] = ~chunk[i];
  // also maybe
  //const uint8x16_t ones = vdupq_n_u8(0xFF);
  // return vbicq_u8(data, ones);
  return vmvnq_u8(data);
}

inline uint8x16_t rotate_bits(uint8x16_t data, int rotation) {
  //chunk[i] = std::rotl(chunk[i], 3);
  //chunk[i] = (chunk[i] << 3) | (chunk[i] >> (8 - 3));
  rotation %= 8;
  // TODO: Find out how we can make clang tell us the different between ARMv8.2a (which compiles here) and ARMv8-a (which does not)
  //return vorrq_u8(vshlq_n_u8(data, rotation), vshrq_n_u8(data, 8 - rotation));
  auto rotation_amounts = vdupq_n_u8(rotation);
  return vorrq_u8(vshlq_u8(data, rotation_amounts), vshlq_u8(data, vsubq_u8(rotation_amounts, vdupq_n_u8(8))));
}

inline uint8x16_t rotate_and_xor(uint8x16_t left_side, int rotation) {
  //chunk[i] ^= (chunk[i] << 2) | (chunk[i] >> (8 - 2));
  //rotation = rotation % 8;
  //rotation %= 8;
  //uint8x16_t rotated = vorrq_u8(vshlq_n_u8(left_side, rotation), vshrq_n_u8(left_side, 8 - rotation));

  // Perform XOR with original data
  return veorq_u8(left_side, rotate_bits(left_side, rotation));
}


inline uint8x16_t add_with_self(uint8x16_t a) {
  //chunk[i] += chunk[i];
  return vaddq_u8(a, a);
}

inline uint8x16_t mul_with_self(uint8x16_t a) {
  
  return vmulq_u8(a, a);
}

inline uint8x16_t and_vectors(uint8x16_t a, uint8x16_t b) {
  //chunk[i] = chunk[i] & chunk[pos2];
  // Perform XOR with original data
  return vandq_u8(a, b);
}

inline uint8x16_t xor_vectors(uint8x16_t a, uint8x16_t b) {
  //chunk[i] ^= chunk[pos2];
  // Perform XOR with original data
  return veorq_u8(a, b);
}

inline uint8x16_t xor_with_bittable(uint8x16_t a) {
  
  //auto count = vcntq_u8(a);
  // Perform XOR with original data
  return veorq_u8(a, vcntq_u8(a));
}

inline uint8x16_t reverse_vector(uint8x16_t data) {
    return vrbitq_u8(data);
}

/*
uint8x16_t shift_left_by_int_with_and(uint8x16_t data, int andint) {
  //chunk[i] = chunk[i] << (chunk[i] & 3);
  // Note: This is signed!
  int8x16_t anded = vandq_s8(data, vdupq_n_u8(andint));
  return vshlq_u8(data, anded);
}
*/

inline uint8x16_t shift_left_by_int_with_and(uint8x16_t data, int andint) {
  //chunk[i] = chunk[i] << (chunk[i] & 3);
  // Note: This is signed!
  //int8x16_t anded = vandq_s8(data, vdupq_n_u8(andint));
  return vshlq_u8(data, vandq_s8(data, vdupq_n_u8(andint)));
}

/*
uint8x16_t shift_right_by_int_with_and(uint8x16_t data, int andint) {
  //chunk[i] = chunk[i] >> (chunk[i] & 3);
  // Note: This is signed!
  int8x16_t anded = vandq_s8(data, vdupq_n_u8(andint));

  // We can negate and left-shift to effectively do a right-shift;
  int8x16_t negated = vqnegq_s8(anded);
  return vshlq_u8(data, negated);
}
*/

inline uint8x16_t shift_right_by_int_with_and(uint8x16_t data, int andint) {
  //chunk[i] = chunk[i] >> (chunk[i] & 3);
  return vshlq_u8(data, vqnegq_s8(vandq_s8(data, vdupq_n_u8(andint))));
}

inline uint8x16_t subtract_xored(uint8x16_t data, int xor_value) {
  //chunk[i] -= (chunk[i] ^ 97);
  //auto xored = veorq_u8(data, vdupq_n_u8(xor_value));
  return vsubq_u8(data, veorq_u8(data, vdupq_n_u8(xor_value)));
}

inline uint8x16_t rotate_by_self(uint8x16_t data) {

  // see rotate_by_self
  //(chunk[i] << (chunk[i] % 8)) | (chunk[i] >> (8 - (chunk[i] % 8)));
  // Shift left by the remainder of each element divided by 8
  uint8x16_t rotation_amounts = vandq_u8(data, vdupq_n_u8(7));

  //for(int x = 0; x < 16; x++) {
  //  printf("mod: %02x\n", rotation_amounts[x]);
  //}

  //uint8x16_t shifted_left = vshlq_u8(data, rotation_amounts);


  //uint8x16_t right_shift_amounts = vsubq_u8(vandq_u8(data, vdupq_n_u8(7)), vdupq_n_u8(8));
  //uint8x16_t right_shift_amounts = vsubq_u8(rotation_amounts, vdupq_n_u8(8));

  // Perform the right shift using left shift with negative amounts
  //return vshlq_u8(data, right_shift_amounts);
  // Shift right by (8 - remainder) of each element


  // Combine the shifted results using bitwise OR
  //return vorrq_u8(shifted_left, vshlq_u8(data, right_shift_amounts));
  return vorrq_u8(vshlq_u8(data, rotation_amounts), vshlq_u8(data, vsubq_u8(rotation_amounts, vdupq_n_u8(8))));

  //chunk[i] = (chunk[i] << (chunk[i] % 8)) | (chunk[i] >> (8 - (chunk[i] % 8)));
  //chunk[i] = std::rotl(chunk[i], chunk[i]);
  //return rotate_bits_by_vector(data);
}

uint32_t branchComputeCPU_aarch64(RC4_KEY key, unsigned char *sData)
{
  unsigned char aarchFixup[256];
  uint64_t lhash = hash_64_fnv1a_256(sData);
  uint64_t prev_lhash = lhash;

  unsigned char *prev_chunk;
  unsigned char *chunk;

  uint64_t tries = 0;
  bool isSame = false;

  unsigned char opt[256];

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

    memcpy(aarchFixup, &chunk[pos2], 16);
    switch (op)
    {
    case 0:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] ^= (unsigned char)bitTable[chunk[i]];             // ones count bits
        chunk[i] = (chunk[i] << 5) | (chunk[i] >> (8 - 5));                // rotate  bits by 5
        chunk[i] *= chunk[i];                             // *
        chunk[i] = (chunk[i] << (chunk[i] % 8)) | (chunk[i] >> (8 - (chunk[i] % 8))); // rotate  bits by random

        // INSERT_RANDOM_CODE_END
        unsigned char t1 = chunk[pos1];
        unsigned char t2 = chunk[pos2];
        chunk[pos1] = reverse8(t2);
        chunk[pos2] = reverse8(t1);
      }
      break;
      case 1:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_left_by_int_with_and(data, 3);
              data = rotate_bits(data, 1);
              data = and_vectors(data, p2vec);
              data = add_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 2:
        {
          opt[op] = true;
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_with_bittable(data);
              data = reverse_vector(data);
              data = shift_left_by_int_with_and(data, 3);
              data = xor_with_bittable(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 3:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_by_self(data);
              data = rotate_bits(data, 3);
              data = xor_vectors(data, p2vec);
              data = rotate_bits(data, 1);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 4:
        {
          opt[op] = true;
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = binary_not(data);
              data = shift_right_by_int_with_and(data, 3);
              data = rotate_by_self(data);
              data = subtract_xored(data, 97);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 5:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_with_bittable(data);
              data = xor_vectors(data, p2vec);
              data = shift_left_by_int_with_and(data, 3);
              data = shift_right_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 6:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_left_by_int_with_and(data, 3);
              data = rotate_bits(data, 3);
              data = binary_not(data);
              data = subtract_xored(data, 97);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 7:
        {
          opt[op] = true;
          memcpy(aarchFixup, &chunk[pos2], 16);
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              // Load 16 bytes (128 bits) of data from chunk
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = add_with_self(data);
              data = rotate_by_self(data);
              data = xor_with_bittable(data);
              data = binary_not(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 8:
        {
          opt[op] = true;
          memcpy(aarchFixup, &chunk[pos2], 16);
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              // Load 16 bytes (128 bits) of data from chunk
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = binary_not(data);
              data = rotate_bits(data, 2);
              data = shift_left_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 9:
        {
          opt[op] = true;
          memcpy(aarchFixup, &chunk[pos2], 16);
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);

          for (int i = pos1; i < pos2; i += 16)
            {
              // Load 16 bytes (128 bits) of data from chunk
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_vectors(data, p2vec);
              data = rotate_and_xor(data, 4);
              data = shift_right_by_int_with_and(data, 3);
              data = rotate_and_xor(data, 2);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 10:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = binary_not(data);
              data = mul_with_self(data);
              data = rotate_bits(data, 3);
              data = mul_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 11:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 6);
              data = and_vectors(data, p2vec);
              data = rotate_by_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 12:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 2);
              data = mul_with_self(data);
              data = rotate_and_xor(data, 2);
              data = binary_not(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 13:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 1);
              data = xor_vectors(data, p2vec);
              data = shift_right_by_int_with_and(data, 3);
              data = rotate_bits(data, 5);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 14:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_right_by_int_with_and(data, 3);
              data = shift_left_by_int_with_and(data, 3);
              data = mul_with_self(data);
              data = shift_left_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 15:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 2);
              data = shift_left_by_int_with_and(data, 3);
              data = and_vectors(data, p2vec);
              data = subtract_xored(data, 97);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 16:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 4);
              data = mul_with_self(data);
              data = rotate_bits(data, 1);
              data = binary_not(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 17:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_vectors(data, p2vec);
              data = mul_with_self(data);
              data = rotate_bits(data, 5);
              data = binary_not(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 18:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 4);
              data = rotate_bits(data, 1);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 19:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = subtract_xored(data, 97);
              data = rotate_bits(data, 5);
              data = shift_left_by_int_with_and(data, 3);
              data = add_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 20:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = and_vectors(data, p2vec);
              data = xor_vectors(data, p2vec);
              data = reverse_vector(data);
              data = rotate_and_xor(data, 2);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 21:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 1);
              data = xor_vectors(data, p2vec);
              data = add_with_self(data);
              data = and_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 22:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_left_by_int_with_and(data, 3);
              data = reverse_vector(data);
              data = mul_with_self(data);
              data = rotate_bits(data, 1);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 23:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 4);
              data = xor_with_bittable(data);
              data = and_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 24:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = add_with_self(data);
              data = shift_right_by_int_with_and(data, 3);
              data = rotate_and_xor(data, 4);
              data = rotate_bits(data, 5);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 25:
        opt[op] = true;
        for (int i = pos1; i < pos2; i += 16)
          {
            // Load 16 bytes (128 bits) of data from chunk
            uint8x16_t data = vld1q_u8(&chunk[i]);
            data = xor_with_bittable(data);
            data = rotate_bits(data, 3);
            data = rotate_by_self(data);
            data = subtract_xored(data, 97);
            vst1q_u8(&chunk[i], data);
          }
        memcpy(&chunk[pos2], aarchFixup, 16);
        break;
      case 26:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = mul_with_self(data);
              data = xor_with_bittable(data);
              data = add_with_self(data);
              data = reverse_vector(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 27:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 5);
              data = and_vectors(data, p2vec);
              data = rotate_and_xor(data, 4);
              data = rotate_bits(data, 5);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 28:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_left_by_int_with_and(data, 3);
              data = add_with_self(data);
              data = add_with_self(data);
              data = rotate_bits(data, 5);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 29:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = mul_with_self(data);
              data = xor_vectors(data, p2vec);
              data = shift_right_by_int_with_and(data, 3);
              data = add_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 30:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = and_vectors(data, p2vec);
              data = rotate_and_xor(data, 4);
              data = rotate_bits(data, 5);
              data = shift_left_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 31:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = binary_not(data);
              data = rotate_and_xor(data, 2);
              data = shift_left_by_int_with_and(data, 3);
              data = mul_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 32:
        {
          opt[op] = true;
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 2);
              data = reverse_vector(data);
              data = rotate_bits(data, 3);
              data = rotate_and_xor(data, 2);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 33:
        opt[op] = true;
        memcpy(aarchFixup, &chunk[pos2], 16);
        for (int i = pos1; i < pos2; i += 16)
          {
            // Load 16 bytes (128 bits) of data from chunk
            uint8x16_t data = vld1q_u8(&chunk[i]);
            data = rotate_by_self(data);
            data = rotate_and_xor(data, 4);
            data = reverse_vector(data);
            data = vmulq_u8(data, data);
            vst1q_u8(&chunk[i], data);
          }
        memcpy(&chunk[pos2], aarchFixup, 16);
        break;
      case 34:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = subtract_xored(data, 97);
              data = shift_left_by_int_with_and(data, 3);
              data = shift_left_by_int_with_and(data, 3);
              data = subtract_xored(data, 97);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 35:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = add_with_self(data);
              data = binary_not(data);
              data = rotate_bits(data, 1);
              data = xor_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 36:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_with_bittable(data);
              data = rotate_bits(data, 1);
              data = rotate_and_xor(data, 2);
              data = rotate_bits(data, 1);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 37:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_by_self(data);
              data = shift_right_by_int_with_and(data, 3);
              data = shift_right_by_int_with_and(data, 3);
              data = mul_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 38:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_right_by_int_with_and(data, 3);
              data = rotate_bits(data, 3);
              data = xor_with_bittable(data);
              data = rotate_by_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 39:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 2);
              data = xor_vectors(data, p2vec);
              data = shift_right_by_int_with_and(data, 3);
              data = and_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 40:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_by_self(data);
              data = xor_vectors(data, p2vec);
              data = xor_with_bittable(data);
              data = xor_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 41:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 5);
              data = subtract_xored(data, 97);
              data = rotate_bits(data, 3);
              data = rotate_and_xor(data, 4);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 42:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 4);
              data = rotate_and_xor(data, 2);
              data = rotate_by_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 43:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = and_vectors(data, p2vec);
              data = add_with_self(data);
              data = and_vectors(data, p2vec);
              data = subtract_xored(data, 97);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 44:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_with_bittable(data);
              data = xor_with_bittable(data);
              data = rotate_bits(data, 3);
              data = rotate_by_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 45:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 2);
              data = and_vectors(data, p2vec);
              data = xor_with_bittable(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 46:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_with_bittable(data);
              data = add_with_self(data);
              data = rotate_bits(data, 5);
              data = rotate_and_xor(data, 4);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 47:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 5);
              data = and_vectors(data, p2vec);
              data = rotate_bits(data, 5);
              data = shift_left_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 48:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_by_self(data);
              data = rotate_bits(data, 5);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 49:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_with_bittable(data);
              data = add_with_self(data);
              data = reverse_vector(data);
              data = rotate_and_xor(data, 4);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 50:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = reverse_vector(data);
              data = rotate_bits(data, 3);
              data = add_with_self(data);
              data = rotate_bits(data, 1);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 51:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_vectors(data, p2vec);
              data = rotate_and_xor(data, 4);
              data = rotate_and_xor(data, 4);
              data = rotate_bits(data, 5);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 52:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_by_self(data);
              data = shift_right_by_int_with_and(data, 3);
              data = binary_not(data);
              data = xor_with_bittable(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 53:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = add_with_self(data);
              data = xor_with_bittable(data);
              data = rotate_and_xor(data, 4);
              data = rotate_and_xor(data, 4);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 54:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = reverse_vector(data);
              data = xor_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 55:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = reverse_vector(data);
              data = rotate_and_xor(data, 4);
              data = rotate_and_xor(data, 4);
              data = rotate_bits(data, 1);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 56:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 2);
              data = mul_with_self(data);
              data = binary_not(data);
              data = rotate_bits(data, 1);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 57:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_by_self(data);
              data = reverse_vector(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 58:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = reverse_vector(data);
              data = rotate_and_xor(data, 2);
              data = and_vectors(data, p2vec);
              data = add_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 59:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 1);
              data = mul_with_self(data);
              data = rotate_by_self(data);
              data = binary_not(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 60:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_vectors(data, p2vec);
              data = binary_not(data);
              data = mul_with_self(data);
              data = rotate_bits(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 61:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 5);
              data = shift_left_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 62:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = and_vectors(data, p2vec);
              data = binary_not(data);
              data = rotate_and_xor(data, 2);
              data = add_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 63:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 5);
              data = xor_with_bittable(data);
              data = subtract_xored(data, 97);
              data = add_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 64:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_vectors(data, p2vec);
              data = reverse_vector(data);
              data = rotate_and_xor(data, 4);
              data = mul_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 65:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 2);
              data = mul_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 66:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 2);
              data = reverse_vector(data);
              data = rotate_and_xor(data, 4);
              data = rotate_bits(data, 1);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 67:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 1);
              data = xor_with_bittable(data);
              data = rotate_and_xor(data, 2);
              data = rotate_bits(data, 5);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 68:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = and_vectors(data, p2vec);
              data = binary_not(data);
              data = rotate_and_xor(data, 4);
              data = xor_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 69:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = add_with_self(data);
              data = mul_with_self(data);
              data = reverse_vector(data);
              data = shift_right_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 70:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_vectors(data, p2vec);
              data = mul_with_self(data);
              data = shift_right_by_int_with_and(data, 3);
              data = rotate_and_xor(data, 4);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 71:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 5);
              data = binary_not(data);
              data = mul_with_self(data);
              data = shift_left_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 72:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = reverse_vector(data);
              data = xor_with_bittable(data);
              data = xor_vectors(data, p2vec);
              data = shift_left_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 73:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_with_bittable(data);
              data = reverse_vector(data);
              data = rotate_bits(data, 5);
              data = subtract_xored(data, 97);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 74:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = mul_with_self(data);
              data = rotate_bits(data, 3);
              data = reverse_vector(data);
              data = and_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 75:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = mul_with_self(data);
              data = xor_with_bittable(data);
              data = and_vectors(data, p2vec);
              data = rotate_and_xor(data, 4);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 76:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_by_self(data);
              data = rotate_and_xor(data, 2);
              data = rotate_bits(data, 5);
              data = shift_right_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 77:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 3);
              data = add_with_self(data);
              data = shift_left_by_int_with_and(data, 3);
              data = xor_with_bittable(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 78:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_by_self(data);
              data = reverse_vector(data);
              data = mul_with_self(data);
              data = subtract_xored(data, 97);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 79:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 4);
              data = rotate_and_xor(data, 2);
              data = add_with_self(data);
              data = mul_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 80:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_by_self(data);
              data = shift_left_by_int_with_and(data, 3);
              data = add_with_self(data);
              data = and_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 81:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 4);
              data = shift_left_by_int_with_and(data, 3);
              data = rotate_by_self(data);
              data = xor_with_bittable(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 82:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_vectors(data, p2vec);
              data = shift_right_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 83:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_left_by_int_with_and(data, 3);
              data = reverse_vector(data);
              data = rotate_bits(data, 3);
              data = reverse_vector(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 84:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = subtract_xored(data, 97);
              data = rotate_bits(data, 1);
              data = shift_left_by_int_with_and(data, 3);
              data = add_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 85:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_right_by_int_with_and(data, 3);
              data = xor_vectors(data, p2vec);
              data = rotate_by_self(data);
              data = shift_left_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 86:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 4);
              data = rotate_by_self(data);
              data = rotate_and_xor(data, 4);
              data = binary_not(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 87:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = add_with_self(data);
              data = rotate_bits(data, 3);
              data = rotate_and_xor(data, 4);
              data = add_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 88:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 2);
              data = rotate_bits(data, 1);
              data = mul_with_self(data);
              data = binary_not(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 89:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = add_with_self(data);
              data = mul_with_self(data);
              data = binary_not(data);
              data = rotate_and_xor(data, 2);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 90:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = reverse_vector(data);
              data = rotate_bits(data, 6);
              data = shift_right_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 91:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_with_bittable(data);
              data = and_vectors(data, p2vec);
              data = rotate_and_xor(data, 4);
              data = reverse_vector(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 92:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_with_bittable(data);
              data = binary_not(data);
              data = xor_with_bittable(data);
              data = and_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 93:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 2);
              data = mul_with_self(data);
              data = and_vectors(data, p2vec);
              data = add_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 94:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 1);
              data = rotate_by_self(data);
              data = and_vectors(data, p2vec);
              data = shift_left_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 95:
        {
          opt[op] = true;
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t vec = vld1q_u8(&chunk[i]);
              // Shift the vector elements to the left by one position
              uint8x16_t shifted_left = vshlq_n_u8(vec, 1);
              uint8x16_t shifted_right = vshrq_n_u8(vec, 8 - 1);
              uint8x16_t rotated = vorrq_u8(shifted_left, shifted_right);
              uint8x16_t data = binary_not(rotated);
              //vmvnq_u8(rotated);
              uint8x16_t shifted_a = rotate_bits(data, 10);
              vst1q_u8(&chunk[i], shifted_a);
            }
          // memcpy(&chunk[pos2], aarchFixup,
          // (pos2-pos1)%16);
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 96:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 2);
              data = rotate_and_xor(data, 2);
              data = xor_with_bittable(data);
              data = rotate_bits(data, 1);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 97:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 1);
              data = shift_left_by_int_with_and(data, 3);
              data = xor_with_bittable(data);
              data = shift_right_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 98:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 4);
              data = shift_left_by_int_with_and(data, 3);
              data = shift_right_by_int_with_and(data, 3);
              data = rotate_and_xor(data, 4);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 99:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 4);
              data = subtract_xored(data, 97);
              data = reverse_vector(data);
              data = shift_right_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 100:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_by_self(data);
              data = shift_left_by_int_with_and(data, 3);
              data = reverse_vector(data);
              data = xor_with_bittable(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 101:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_right_by_int_with_and(data, 3);
              data = xor_with_bittable(data);
              data = shift_right_by_int_with_and(data, 3);
              data = binary_not(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 102:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 3);
              data = subtract_xored(data, 97);
              data = add_with_self(data);
              data = rotate_bits(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 103:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 1);
              data = reverse_vector(data);
              data = xor_vectors(data, p2vec);
              data = rotate_by_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 104:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = reverse_vector(data);
              data = xor_with_bittable(data);
              data = rotate_bits(data, 5);
              data = add_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 105:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_left_by_int_with_and(data, 3);
              data = rotate_bits(data, 3);
              data = rotate_by_self(data);
              data = rotate_and_xor(data, 2);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 106:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = reverse_vector(data);
              data = rotate_and_xor(data, 4);
              data = rotate_bits(data, 1);
              data = mul_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 107:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_right_by_int_with_and(data, 3);
              data = rotate_and_xor(data, 2);
              data = rotate_bits(data, 6);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 108:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_vectors(data, p2vec);
              data = binary_not(data);
              data = and_vectors(data, p2vec);
              data = rotate_and_xor(data, 2);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 109:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = mul_with_self(data);
              data = rotate_by_self(data);
              data = xor_vectors(data, p2vec);
              data = rotate_and_xor(data, 2);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 110:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = add_with_self(data);
              data = rotate_and_xor(data, 2);
              data = rotate_and_xor(data, 2);
              data = shift_right_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 111:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = mul_with_self(data);
              data = reverse_vector(data);
              data = mul_with_self(data);
              data = shift_right_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 112:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 3);
              data = binary_not(data);
              data = rotate_bits(data, 5);
              data = subtract_xored(data, 97);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 113:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 6);
              data = xor_with_bittable(data);
              data = binary_not(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 114:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 1);
              data = reverse_vector(data);
              data = rotate_by_self(data);
              data = binary_not(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 115:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_by_self(data);
              data = rotate_bits(data, 5);
              data = and_vectors(data, p2vec);
              data = rotate_bits(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 116:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = and_vectors(data, p2vec);
              data = xor_vectors(data, p2vec);
              data = xor_with_bittable(data);
              data = shift_left_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 117:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_left_by_int_with_and(data, 3);
              data = rotate_bits(data, 3);
              data = shift_left_by_int_with_and(data, 3);
              data = and_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 118:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_right_by_int_with_and(data, 3);
              data = add_with_self(data);
              data = shift_left_by_int_with_and(data, 3);
              data = rotate_bits(data, 5);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 119:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = reverse_vector(data);
              data = rotate_and_xor(data, 2);
              data = binary_not(data);
              data = xor_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 120:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 2);
              data = mul_with_self(data);
              data = xor_vectors(data, p2vec);
              data = reverse_vector(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 121:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_right_by_int_with_and(data, 3);
              data = add_with_self(data);
              data = xor_with_bittable(data);
              data = mul_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 122:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 4);
              data = rotate_by_self(data);
              data = rotate_bits(data, 5);
              data = data = rotate_and_xor(data, 2);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 123:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = and_vectors(data, p2vec);
              data = binary_not(data);
              data = rotate_bits(data, 6);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 124:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 2);
              data = rotate_and_xor(data, 2);
              data = xor_vectors(data, p2vec);
              data = binary_not(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 125:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = reverse_vector(data);
              data = rotate_and_xor(data, 2);
              data = add_with_self(data);
              data = shift_right_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 126:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 1);
              data = reverse_vector(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 127:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_left_by_int_with_and(data, 3);
              data = mul_with_self(data);
              data = and_vectors(data, p2vec);
              data = xor_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 128:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_by_self(data);
              data = rotate_and_xor(data, 2);
              data = rotate_and_xor(data, 2);
              data = rotate_bits(data, 5);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 129:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = binary_not(data);
              data = xor_with_bittable(data);
              data = xor_with_bittable(data);
              data = shift_right_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 130:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_right_by_int_with_and(data, 3);
              data = rotate_by_self(data);
              data = rotate_bits(data, 1);
              data = rotate_and_xor(data, 4);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 131:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = subtract_xored(data, 97);
              data = rotate_bits(data, 1);
              data = xor_with_bittable(data);
              data = mul_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 132:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = and_vectors(data, p2vec);
              data = reverse_vector(data);
              data = rotate_bits(data, 5);
              data = rotate_and_xor(data, 2);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 133:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_vectors(data, p2vec);
              data = rotate_bits(data, 5);
              data = rotate_and_xor(data, 2);
              data = shift_left_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 134:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = binary_not(data);
              data = rotate_and_xor(data, 4);
              data = rotate_bits(data, 1);
              data = and_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 135:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_right_by_int_with_and(data, 3);
              data = rotate_and_xor(data, 2);
              data = add_with_self(data);
              data = reverse_vector(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 136:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_right_by_int_with_and(data, 3);
              data = subtract_xored(data, 97);
              data = xor_vectors(data, p2vec);
              data = rotate_bits(data, 5);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 137:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 5);
              data = shift_right_by_int_with_and(data, 3);
              data = reverse_vector(data);
              data = rotate_by_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 138:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_vectors(data, p2vec);
              data = xor_vectors(data, p2vec);
              data = add_with_self(data);
              data = subtract_xored(data, 97);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 139:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 2);
              data = rotate_bits(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 140:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 1);
              data = rotate_and_xor(data, 2);
              data = xor_vectors(data, p2vec);
              data = rotate_bits(data, 5);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 141:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 1);
              data = subtract_xored(data, 97);
              data = xor_with_bittable(data);
              data = add_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 142:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = and_vectors(data, p2vec);
              data = rotate_bits(data, 5);
              data = reverse_vector(data);
              data = rotate_and_xor(data, 2);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 143:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = and_vectors(data, p2vec);
              data = rotate_bits(data, 3);
              data = shift_right_by_int_with_and(data, 3);
              data = shift_left_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 144:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_by_self(data);
              data = shift_left_by_int_with_and(data, 3);
              data = binary_not(data);
              data = rotate_by_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 145:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = reverse_vector(data);
              data = rotate_and_xor(data, 4);
              data = rotate_and_xor(data, 2);
              data = rotate_and_xor(data, 4);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 146:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = and_vectors(data, p2vec);
              data = shift_left_by_int_with_and(data, 3);
              data = and_vectors(data, p2vec);
              data = xor_with_bittable(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 147:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = binary_not(data);
              data = shift_left_by_int_with_and(data, 3);
              data = rotate_and_xor(data, 4);
              data = mul_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 148:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = and_vectors(data, p2vec);
              data = rotate_bits(data, 5);
              data = shift_left_by_int_with_and(data, 3);
              data = subtract_xored(data, 97);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 149:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_vectors(data, p2vec);
              data = reverse_vector(data);
              data = subtract_xored(data, 97);
              data = add_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 150:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_left_by_int_with_and(data, 3);
              data = shift_left_by_int_with_and(data, 3);
              data = shift_left_by_int_with_and(data, 3);
              data = and_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 151:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = add_with_self(data);
              data = shift_left_by_int_with_and(data, 3);
              data = mul_with_self(data);
              data = shift_left_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 152:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_right_by_int_with_and(data, 3);
              data = binary_not(data);
              data = shift_left_by_int_with_and(data, 3);
              data = rotate_and_xor(data, 2);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 153:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 4);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 154:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 5);
              data = binary_not(data);
              data = xor_vectors(data, p2vec);
              data = xor_with_bittable(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 155:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = subtract_xored(data, 97);
              data = xor_vectors(data, p2vec);
              data = xor_with_bittable(data);
              data = xor_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 156:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_right_by_int_with_and(data, 3);
              data = shift_right_by_int_with_and(data, 3);
              data = rotate_bits(data, 4);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 157:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_right_by_int_with_and(data, 3);
              data = shift_left_by_int_with_and(data, 3);
              data = rotate_by_self(data);
              data = rotate_bits(data, 1);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 158:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_with_bittable(data);
              data = rotate_bits(data, 3);
              data = add_with_self(data);
              data = rotate_bits(data, 1);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 159:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = subtract_xored(data, 97);
              data = xor_vectors(data, p2vec);
              data = rotate_by_self(data);
              data = xor_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 160:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_right_by_int_with_and(data, 3);
              data = reverse_vector(data);
              data = rotate_bits(data, 4);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 161:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_vectors(data, p2vec);
              data = xor_vectors(data, p2vec);
              data = rotate_bits(data, 5);
              data = rotate_by_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 162:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = mul_with_self(data);
              data = reverse_vector(data);
              data = rotate_and_xor(data, 2);
              data = subtract_xored(data, 97);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 163:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_left_by_int_with_and(data, 3);
              data = subtract_xored(data, 97);
              data = rotate_and_xor(data, 4);
              data = rotate_bits(data, 1);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 164:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = mul_with_self(data);
              data = xor_with_bittable(data);
              data = subtract_xored(data, 97);
              data = binary_not(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 165:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 4);
              data = xor_vectors(data, p2vec);
              data = shift_left_by_int_with_and(data, 3);
              data = add_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 166:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 3);
              data = add_with_self(data);
              data = rotate_and_xor(data, 2);
              data = binary_not(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 167:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = mul_with_self(data);
              data = shift_right_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 168:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_by_self(data);
              data = and_vectors(data, p2vec);
              data = rotate_by_self(data);
              data = rotate_bits(data, 1);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 169:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 1);
              data = shift_left_by_int_with_and(data, 3);
              data = rotate_and_xor(data, 4);
              data = and_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 170:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = subtract_xored(data, 97);
              data = reverse_vector(data);
              data = subtract_xored(data, 97);
              data = mul_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 171:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 3);
              data = subtract_xored(data, 97);
              data = xor_with_bittable(data);
              data = reverse_vector(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 172:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 4);
              data = subtract_xored(data, 97);
              data = shift_left_by_int_with_and(data, 3);
              data = rotate_bits(data, 1);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 173:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = binary_not(data);
              data = shift_left_by_int_with_and(data, 3);
              data = mul_with_self(data);
              data = add_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 174:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = binary_not(data);
              data = rotate_by_self(data);
              data = xor_with_bittable(data);
              data = xor_with_bittable(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 175:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 3);
              data = subtract_xored(data, 97);
              data = mul_with_self(data);
              data = rotate_bits(data, 5);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 176:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_vectors(data, p2vec);
              data = mul_with_self(data);
              data = xor_vectors(data, p2vec);
              data = rotate_bits(data, 5);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 177:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_with_bittable(data);
              data = rotate_and_xor(data, 2);
              data = rotate_and_xor(data, 2);
              data = and_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 178:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = and_vectors(data, p2vec);
              data = add_with_self(data);
              data = binary_not(data);
              data = rotate_bits(data, 1);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 179:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 2);
              data = add_with_self(data);
              data = shift_right_by_int_with_and(data, 3);
              data = reverse_vector(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 180:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_right_by_int_with_and(data, 3);
              data = rotate_and_xor(data, 4);
              data = xor_vectors(data, p2vec);
              data = subtract_xored(data, 97);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 181:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = binary_not(data);
              data = shift_left_by_int_with_and(data, 3);
              data = rotate_and_xor(data, 2);
              data = rotate_bits(data, 5);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 182:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_vectors(data, p2vec);
              data = rotate_bits(data, 6);
              data = rotate_and_xor(data, 4);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 183:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = add_with_self(data);
              data = subtract_xored(data, 97);
              data = subtract_xored(data, 97);
              data = mul_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 184:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_left_by_int_with_and(data, 3);
              data = mul_with_self(data);
              data = rotate_bits(data, 5);
              data = xor_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 185:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = binary_not(data);
              data = rotate_and_xor(data, 4);
              data = rotate_bits(data, 5);
              data = shift_right_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 186:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 2);
              data = rotate_and_xor(data, 4);
              data = subtract_xored(data, 97);
              data = shift_right_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 187:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_vectors(data, p2vec);
              data = binary_not(data);
              data = add_with_self(data);
              data = rotate_bits(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 188:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 4);
              data = xor_with_bittable(data);
              data = rotate_and_xor(data, 4);
              data = rotate_and_xor(data, 4);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 189:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 5);
              data = rotate_and_xor(data, 4);
              data = xor_vectors(data, p2vec);
              data = subtract_xored(data, 97);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 190:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 5);
              data = shift_right_by_int_with_and(data, 3);
              data = and_vectors(data, p2vec);
              data = rotate_and_xor(data, 2);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 191:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = add_with_self(data);
              data = rotate_bits(data, 3);
              data = rotate_by_self(data);
              data = shift_right_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 192:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = add_with_self(data);
              data = shift_left_by_int_with_and(data, 3);
              data = add_with_self(data);
              data = mul_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 193:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = and_vectors(data, p2vec);
              data = shift_left_by_int_with_and(data, 3);
              data = rotate_by_self(data);
              data = rotate_bits(data, 1);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 194:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = and_vectors(data, p2vec);
              data = rotate_by_self(data);
              data = shift_left_by_int_with_and(data, 3);
              data = and_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 195:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_with_bittable(data);
              data = rotate_and_xor(data, 2);
              data = xor_vectors(data, p2vec);
              data = rotate_and_xor(data, 4);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 196:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 3);
              data = reverse_vector(data);
              data = shift_left_by_int_with_and(data, 3);
              data = rotate_bits(data, 1);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 197:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 4);
              data = rotate_by_self(data);
              data = mul_with_self(data);
              data = mul_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 198:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_right_by_int_with_and(data, 3);
              data = shift_right_by_int_with_and(data, 3);
              data = reverse_vector(data);
              data = rotate_bits(data, 1);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 199:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = binary_not(data);
              data = add_with_self(data);
              data = mul_with_self(data);
              data = xor_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 200:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_right_by_int_with_and(data, 3);
              data = xor_with_bittable(data);
              data = reverse_vector(data);
              data = reverse_vector(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 201:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 3);
              data = rotate_and_xor(data, 2);
              data = rotate_and_xor(data, 4);
              data = binary_not(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 202:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_vectors(data, p2vec);
              data = binary_not(data);
              data = rotate_by_self(data);
              data = rotate_bits(data, 5);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 203:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_vectors(data, p2vec);
              data = and_vectors(data, p2vec);
              data = rotate_bits(data, 1);
              data = rotate_by_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 204:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 5);
              data = rotate_and_xor(data, 2);
              data = rotate_by_self(data);
              data = xor_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 205:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_with_bittable(data);
              data = rotate_and_xor(data, 4);
              data = shift_left_by_int_with_and(data, 3);
              data = add_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 206:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 4);
              data = reverse_vector(data);
              data = reverse_vector(data);
              data = xor_with_bittable(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 207:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_with_bittable(data);
              data = xor_with_bittable(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 208:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = add_with_self(data);
              data = add_with_self(data);
              data = shift_right_by_int_with_and(data, 3);
              data = rotate_bits(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 209:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 5);
              data = reverse_vector(data);
              data = xor_with_bittable(data);
              data = subtract_xored(data, 97);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 210:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 2);
              data = rotate_by_self(data);
              data = rotate_bits(data, 5);
              data = binary_not(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 211:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 4);
              data = add_with_self(data);
              data = subtract_xored(data, 97);
              data = rotate_by_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 212:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_by_self(data);
              data = rotate_and_xor(data, 2);
              data = xor_vectors(data, p2vec);
              data = xor_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 213:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = add_with_self(data);
              data = shift_left_by_int_with_and(data, 3);
              data = rotate_bits(data, 3);
              data = subtract_xored(data, 97);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 214:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_vectors(data, p2vec);
              data = subtract_xored(data, 97);
              data = shift_right_by_int_with_and(data, 3);
              data = binary_not(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 215:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_vectors(data, p2vec);
              data = and_vectors(data, p2vec);
              data = shift_left_by_int_with_and(data, 3);
              data = mul_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 216:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_by_self(data);
              data = binary_not(data);
              data = subtract_xored(data, 97);
              data = and_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 217:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 5);
              data = add_with_self(data);
              data = rotate_bits(data, 1);
              data = rotate_and_xor(data, 4);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 218:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = reverse_vector(data);
              data = binary_not(data);
              data = mul_with_self(data);
              data = subtract_xored(data, 97);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 219:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 4);
              data = rotate_bits(data, 3);
              data = and_vectors(data, p2vec);
              data = reverse_vector(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 220:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 1);
              data = shift_left_by_int_with_and(data, 3);
              data = reverse_vector(data);
              data = shift_left_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 221:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 5);
              data = xor_vectors(data, p2vec);
              data = binary_not(data);
              data = reverse_vector(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 222:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = shift_right_by_int_with_and(data, 3);
              data = shift_left_by_int_with_and(data, 3);
              data = xor_vectors(data, p2vec);
              data = mul_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 223:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 3);
              data = xor_vectors(data, p2vec);
              data = rotate_by_self(data);
              data = subtract_xored(data, 97);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 224:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 2);
              data = rotate_bits(data, 4);
              data = shift_left_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 225:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = binary_not(data);
              data = shift_right_by_int_with_and(data, 3);
              data = reverse_vector(data);
              data = rotate_bits(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 226:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = reverse_vector(data);
              data = subtract_xored(data, 97);
              data = mul_with_self(data);
              data = xor_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 227:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = binary_not(data);
              data = shift_left_by_int_with_and(data, 3);
              data = subtract_xored(data, 97);
              data = and_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 228:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = add_with_self(data);
              data = shift_right_by_int_with_and(data, 3);
              data = add_with_self(data);
              data = xor_with_bittable(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 229:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 3);
              data = rotate_by_self(data);
              data = rotate_and_xor(data, 2);
              data = xor_with_bittable(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 230:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = mul_with_self(data);
              data = and_vectors(data, p2vec);
              data = rotate_by_self(data);
              data = rotate_by_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 231:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 3);
              data = shift_right_by_int_with_and(data, 3);
              data = xor_vectors(data, p2vec);
              data = reverse_vector(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 232:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = mul_with_self(data);
              data = mul_with_self(data);
              data = rotate_and_xor(data, 4);
              data = rotate_bits(data, 5);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 233:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 1);
              data = xor_with_bittable(data);
              data = rotate_bits(data, 3);
              data = xor_with_bittable(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 234:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = and_vectors(data, p2vec);
              data = mul_with_self(data);
              data = shift_right_by_int_with_and(data, 3);
              data = xor_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 235:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 2);
              data = mul_with_self(data);
              data = rotate_bits(data, 3);
              data = binary_not(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 236:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = xor_vectors(data, p2vec);
              data = add_with_self(data);
              data = and_vectors(data, p2vec);
              data = subtract_xored(data, 97);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 237:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 5);
              data = shift_left_by_int_with_and(data, 3);
              data = rotate_and_xor(data, 2);
              data = rotate_bits(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 238:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = add_with_self(data);
              data = add_with_self(data);
              data = rotate_bits(data, 3);
              data = subtract_xored(data, 97);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 239:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 6);
              data = mul_with_self(data);
              data = and_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 240:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = binary_not(data);
              data = add_with_self(data);
              data = and_vectors(data, p2vec);
              data = shift_left_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 241:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_and_xor(data, 4);
              data = xor_with_bittable(data);
              data = xor_vectors(data, p2vec);
              data = rotate_bits(data, 1);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 242:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = add_with_self(data);
              data = add_with_self(data);
              data = subtract_xored(data, 97);
              data = xor_vectors(data, p2vec);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 243:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 5);
              data = rotate_and_xor(data, 2);
              data = xor_with_bittable(data);
              data = rotate_bits(data, 1);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 244:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = binary_not(data);
              data = rotate_and_xor(data, 2);
              data = reverse_vector(data);
              data = rotate_bits(data, 5);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 245:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = subtract_xored(data, 97);
              data = rotate_bits(data, 5);
              data = rotate_and_xor(data, 2);
              data = shift_right_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 246:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = add_with_self(data);
              data = rotate_bits(data, 1);
              data = shift_right_by_int_with_and(data, 3);
              data = add_with_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 247:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = rotate_bits(data, 5);
              data = rotate_and_xor(data, 2);
              data = rotate_bits(data, 5);
              data = binary_not(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 248:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = binary_not(data);
              data = subtract_xored(data, 97);
              data = xor_with_bittable(data);
              data = rotate_bits(data, 5);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 249:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = reverse_vector(data);
              data = rotate_and_xor(data, 4);
              data = rotate_and_xor(data, 4);
              data = rotate_by_self(data);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 250:
        {
          opt[op] = true;
          uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = and_vectors(data, p2vec);
              data = rotate_by_self(data);
              data = xor_with_bittable(data);
              data = rotate_and_xor(data, 4);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 251:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = add_with_self(data);
              data = xor_with_bittable(data);
              data = reverse_vector(data);
              data = rotate_and_xor(data, 2);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
      case 252:
        {
          opt[op] = true;
          // uint8x16_t p2vec = vdupq_n_u8(chunk[pos2]);
          for (int i = pos1; i < pos2; i += 16)
            {
              uint8x16_t data = vld1q_u8(&chunk[i]);
              data = reverse_vector(data);
              data = rotate_and_xor(data, 4);
              data = rotate_and_xor(data, 2);
              data = shift_left_by_int_with_and(data, 3);
              vst1q_u8(&chunk[i], data);
            }
          memcpy(&chunk[pos2], aarchFixup, 16);
        }
        break;
    case 253:
#pragma GCC unroll 32
      for (int i = pos1; i < pos2; i++)
      {
        // INSERT_RANDOM_CODE_START
        chunk[i] = (chunk[i] << 3) | (chunk[i] >> (8 - 3));  // rotate  bits by 3
        chunk[i] ^= (chunk[i] << 2) | (chunk[i] >> (8 - 2)); // rotate  bits by 2
        chunk[i] ^= chunk[pos2];     // XOR
        chunk[i] = (chunk[i] << 3) | (chunk[i] >> (8 - 3));  // rotate  bits by 3
        // INSERT_RANDOM_CODE_END

        prev_lhash = lhash + prev_lhash;
        lhash = XXHash64::hash(chunk, pos2,0);
        //lhash = XXH64(chunk, pos2, 0);
        //lhash = XXH3_64bits(chunk, pos2);
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
        chunk[i] = (chunk[i] << 3) | (chunk[i] >> (8 - 3));                                  // rotate  bits by 3
        chunk[i] ^= (chunk[i] << 2) | (chunk[i] >> (8 - 2));                                 // rotate  bits by 2
        chunk[i] = (chunk[i] << 3) | (chunk[i] >> (8 - 3));                                  // rotate  bits by 3
                                                                                            // INSERT_RANDOM_CODE_END
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