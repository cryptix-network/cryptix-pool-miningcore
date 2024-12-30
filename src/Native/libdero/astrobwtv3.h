/*
Copyright 2024 Cedric CRISPIN (cedric-crispin.com)
Authors: Cedric CRISPIN (cedric.crispin@gmail.com)
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef ASTROBWTV3_H
#define ASTROBWTV3_H

#include <algorithm>
#include <bitset>
#include <iostream>
#include <cstdint>
#include <cstring>
#include <bitset>
#include <utility>
#include <numeric>
#include "include/Salsa20.h"
#include <openssl/sha.h>
#include <openssl/rc4.h>

#ifdef _WIN32
#include <winsock2.h>
#include <intrin.h>
#else
#include <arpa/inet.h>
#endif

#include "include/libsais/libsais.h"

#if defined(__x86_64__)
  #include "immintrin.h"
#endif
#if defined(__aarch64__)
  #include <arm_neon.h>
#endif

const uint32_t MAX_LENGTH = (256 * 384) - 1; // this is the maximum

// The base for the following code was contributed by @Wolf9466 on Discord
// Last instruction is a special case, and duplicated.
const uint32_t CodeLUT[256] =
{
    0x090F020A, 0x060B0500, 0x09080609, 0x0A0D030B, 0x04070A01, 0x09030607, 0x060D0401, 0x000A0904,
    0x040F0F06, 0x030E070C, 0x04020D02, 0x0B0F050A, 0x0C020C04, 0x0B03070F, 0x07060206, 0x0C060501,
    0x0E020B04, 0x03020F04, 0x0E0D0B0F, 0x010F0600, 0x0503080C, 0x0B030005, 0x0608020B, 0x0D0B0905,
    0x00070E0F, 0x090D0A01, 0x02090008, 0x0F050E0F, 0x0600000F, 0x02030700, 0x050E0F06, 0x040C0602,
    0x0C080D0C, 0x0A0E0802, 0x01060601, 0x00040B03, 0x090B0C0B, 0x0A070702, 0x070D090A, 0x0C030705,
    0x0A030903, 0x0F010D0E, 0x0B0D0C0A, 0x05000501, 0x09090D0A, 0x0F0F0509, 0x09000F0E, 0x0F050F06,
    0x0A04040F, 0x0900080E, 0x080D000B, 0x030E0E0F, 0x0A070409, 0x00090E0E, 0x08030404, 0x080E0E0B,
    0x0C02040B, 0x0A0F0D08, 0x080C0500, 0x0B020A04, 0x0304020D, 0x0F060D0F, 0x05040C00, 0x0F090100,
    0x03080E02, 0x0F0D0C02, 0x0C080E0B, 0x0B090C0F, 0x05040E03, 0x00020807, 0x0302070E, 0x0F040206,
    0x08090306, 0x09080F01, 0x020D0805, 0x0209050E, 0x0A0C0F07, 0x0D000609, 0x0A080201, 0x0E0C0002,
    0x0A060005, 0x0E060A09, 0x03040407, 0x06080D08, 0x010B0600, 0x07030A06, 0x0E0A0E04, 0x000D0E00,
    0x0C0B0204, 0x0002040C, 0x080F0B07, 0x09050E08, 0x09040905, 0x0C020500, 0x0B0A0506, 0x0B040F0F,
    0x0C0C090B, 0x0B060907, 0x0E06070E, 0x0E010807, 0x0A060809, 0x07090704, 0x0D01000D, 0x0B08030A,
    0x08090F00, 0x060D0A0C, 0x080E0B02, 0x070C0F0B, 0x0304050C, 0x020A030C, 0x000C0C07, 0x02080207,
    0x0D040F01, 0x0F0B0904, 0x0B080A04, 0x0A0F050D, 0x05030906, 0x060D0605, 0x0700060F, 0x080C0403,
    0x0C020308, 0x07000902, 0x0E0A0F0C, 0x05040D0D, 0x0C0C0304, 0x080C0007, 0x0D0B0F08, 0x06020503,
    0x0A0C0C0F, 0x04090907, 0x070A0B0E, 0x010B0902, 0x05080F0C, 0x030F0C06, 0x040E0B05, 0x070C0008,
    0x0701030F, 0x0F07080A, 0x03030001, 0x0F0D0C0D, 0x0B0C030F, 0x0B010900, 0x050F080C, 0x050D0706,
    0x0A06040A, 0x080E0C0E, 0x05060509, 0x04060E02, 0x050F0601, 0x03080100, 0x06060605, 0x00060206,
    0x0704060C, 0x0B0D0404, 0x0F040309, 0x01030903, 0x07070D0B, 0x07060A0B, 0x090D000B, 0x01030A03,
    0x07080B0D, 0x03030F0A, 0x02080C01, 0x06010E0B, 0x02090104, 0x0E030600, 0x0D000C04, 0x04040207,
    0x0A050A0B, 0x0B060E05, 0x01080102, 0x0D010908, 0x0E01060B, 0x04060200, 0x040A0909, 0x0D01020F,
    0x0302030F, 0x090C0C05, 0x0500040B, 0x0C000708, 0x070E0301, 0x04060C0F, 0x030B0F0E, 0x00010102,
    0x06020F03, 0x040E0F07, 0x0C0E0107, 0x0304000D, 0x0E090E0E, 0x0F0E0301, 0x0F07050C, 0x000D0A07,
    0x00060002, 0x05060A0B, 0x050A0605, 0x090C030E, 0x0D08060B, 0x0E0A0202, 0x0707080B, 0x04000203,
    0x07090808, 0x0D0C0E04, 0x03040A0F, 0x03050B0A, 0x0F0C0A03, 0x090E0600, 0x0E080809, 0x0F0D0909,
    0x0000070D, 0x0F080901, 0x0C0A0F04, 0x0E00010A, 0x0A0C0303, 0x00060D01, 0x03010704, 0x03050602,
    0x0A040105, 0x0F000B0E, 0x08040201, 0x0E0D0508, 0x0B060806, 0x0F030408, 0x07060302, 0x0D030A01,
    0x0C0B0D06, 0x0407080D, 0x08010203, 0x04060105, 0x00070009, 0x0D0A0C09, 0x02050A0A, 0x0D070308,
    0x02020E0F, 0x0B090D09, 0x05020703, 0x0C020D04, 0x03000501, 0x0F060C0D, 0x00000D01, 0x0F0B0205,
    0x04000506, 0x0E09030B, 0x00000103, 0x0F0C090B, 0x040C080F, 0x010F0C07, 0x000B0700, 0x0F0C0F04,
    0x0401090F, 0x080E0E0A, 0x050A090E, 0x0009080C, 0x080E0C06, 0x0D0C030D, 0x090D0C0D, 0x090D0C0D
};

#if defined(__AVX2__)

#ifdef __GNUC__ 
#if __GNUC__ < 8
#define _mm256_set_m128i(xmm1, xmm2) _mm256_permute2f128_si256(_mm256_castsi128_si256(xmm1), _mm256_castsi128_si256(xmm2), 2)
#define _mm256_set_m128f(xmm1, xmm2) _mm256_permute2f128_ps(_mm256_castps128_ps256(xmm1), _mm256_castps128_ps256(xmm2), 2)
#endif
#endif

#define ALIGNMENT 32

const __m256i vec_3 = _mm256_set1_epi8(3);

inline __m256i genMask(int i) {
  __m256i temp = _mm256_setzero_si256(); // Initialize mask with all zeros

  __m128i lower_part = _mm_set1_epi64x(0);
  __m128i upper_part = _mm_set1_epi64x(0);

  if (i > 24) {
    lower_part = _mm_set1_epi64x(-1ULL);
    upper_part = _mm_set_epi64x(-1ULL >> (32-i)*8,-1ULL);
  } else if (i > 16) {
    lower_part = _mm_set_epi64x(-1ULL,-1ULL);
    upper_part = _mm_set_epi64x(0,-1ULL >> (24-i)*8);
  } else if (i > 8) {
    lower_part = _mm_set_epi64x(-1ULL >> (16-i)*8,-1ULL);
  } else if (i > 0) {
    lower_part = _mm_set_epi64x(0,-1ULL >> (8-i)*8);
  }

  temp = _mm256_insertf128_si256(temp, lower_part, 0); // Set lower 128 bits
  temp = _mm256_insertf128_si256(temp, upper_part, 1); // Set upper 128 bits
  return temp;
}

inline __m128i mullo_epi8(__m128i a, __m128i b)
{
    // unpack and multiply
    __m128i dst_even = _mm_mullo_epi16(a, b);
    __m128i dst_odd = _mm_mullo_epi16(_mm_srli_epi16(a, 8),_mm_srli_epi16(b, 8));
    // repack
#if defined(__AVX2__)
    // only faster if have access to VPBROADCASTW
    return _mm_or_si128(_mm_slli_epi16(dst_odd, 8), _mm_and_si128(dst_even, _mm_set1_epi16(0xFF)));
#else
    return _mm_or_si128(_mm_slli_epi16(dst_odd, 8), _mm_srli_epi16(_mm_slli_epi16(dst_even,8), 8));
#endif
}

inline __m256i _mm256_mul_epi8(__m256i x, __m256i y) {
  // Unpack and isolate 2 8 bit numbers from a 16 bit block in each vector using masks
  __m256i mask1 = _mm256_set1_epi16(0xFF00);
  __m256i mask2 = _mm256_set1_epi16(0x00FF);

  // Store the first and second members of the 8bit multiplication equation in their own 16 bit numbers, shifting down as necessary before calculating
  __m256i aa = _mm256_srli_epi16(_mm256_and_si256(x, mask1), 8);
  __m256i ab = _mm256_srli_epi16(_mm256_and_si256(y, mask1), 8);
  __m256i ba = _mm256_and_si256(x, mask2);
  __m256i bb = _mm256_and_si256(y, mask2);

  // Perform the multiplication, and undo any downshifting
  __m256i pa = _mm256_slli_epi16(_mm256_mullo_epi16(aa, ab), 8);
  __m256i pb = _mm256_mullo_epi16(ba, bb);

  // Mask out unwanted data to maintain isolation
  pa = _mm256_and_si256(pa, mask1);
  pb = _mm256_and_si256(pb, mask2);

  __m256i result = _mm256_or_si256(pa,pb);

  return result;
}

inline __m256i _mm256_sllv_epi8(__m256i a, __m256i count) {
    __m256i mask_hi        = _mm256_set1_epi32(0xFF00FF00);
    __m256i multiplier_lut = _mm256_set_epi8(0,0,0,0, 0,0,0,0, 0x80,0x40,0x20,0x10, 0x08,0x04,0x02,0x01, 0,0,0,0, 0,0,0,0, 0x80,0x40,0x20,0x10, 0x08,0x04,0x02,0x01);

    __m256i count_sat      = _mm256_min_epu8(count, _mm256_set1_epi8(8));     /* AVX shift counts are not masked. So a_i << n_i = 0 for n_i >= 8. count_sat is always less than 9.*/ 
    __m256i multiplier     = _mm256_shuffle_epi8(multiplier_lut, count_sat);  /* Select the right multiplication factor in the lookup table.                                      */
    
    __m256i x_lo           = _mm256_mullo_epi16(a, multiplier);               /* Unfortunately _mm256_mullo_epi8 doesn't exist. Split the 16 bit elements in a high and low part. */

    __m256i multiplier_hi  = _mm256_srli_epi16(multiplier, 8);                /* The multiplier of the high bits.                                                                 */
    __m256i a_hi           = _mm256_and_si256(a, mask_hi);                    /* Mask off the low bits.                                                                           */
    __m256i x_hi           = _mm256_mullo_epi16(a_hi, multiplier_hi);
    __m256i x              = _mm256_blendv_epi8(x_lo, x_hi, mask_hi);         /* Merge the high and low part. */

    return x;
}


inline __m256i _mm256_srlv_epi8(__m256i a, __m256i count) {
    __m256i mask_hi        = _mm256_set1_epi32(0xFF00FF00);
    __m256i multiplier_lut = _mm256_set_epi8(0,0,0,0, 0,0,0,0, 0x01,0x02,0x04,0x08, 0x10,0x20,0x40,0x80, 0,0,0,0, 0,0,0,0, 0x01,0x02,0x04,0x08, 0x10,0x20,0x40,0x80);

    __m256i count_sat      = _mm256_min_epu8(count, _mm256_set1_epi8(8));     /* AVX shift counts are not masked. So a_i >> n_i = 0 for n_i >= 8. count_sat is always less than 9.*/ 
    __m256i multiplier     = _mm256_shuffle_epi8(multiplier_lut, count_sat);  /* Select the right multiplication factor in the lookup table.                                      */
    __m256i a_lo           = _mm256_andnot_si256(mask_hi, a);                 /* Mask off the high bits.                                                                          */
    __m256i multiplier_lo  = _mm256_andnot_si256(mask_hi, multiplier);        /* The multiplier of the low bits.                                                                  */
    __m256i x_lo           = _mm256_mullo_epi16(a_lo, multiplier_lo);         /* Shift left a_lo by multiplying.                                                                  */
            x_lo           = _mm256_srli_epi16(x_lo, 7);                      /* Shift right by 7 to get the low bits at the right position.                                      */

    __m256i multiplier_hi  = _mm256_and_si256(mask_hi, multiplier);           /* The multiplier of the high bits.                                                                 */
    __m256i x_hi           = _mm256_mulhi_epu16(a, multiplier_hi);            /* Variable shift left a_hi by multiplying. Use a instead of a_hi because the a_lo bits don't interfere */
            x_hi           = _mm256_slli_epi16(x_hi, 1);                      /* Shift left by 1 to get the high bits at the right position.                                      */
    __m256i x              = _mm256_blendv_epi8(x_lo, x_hi, mask_hi);         /* Merge the high and low part.                                                                     */

    return x;
}

inline __m256i _mm256_rolv_epi8(__m256i x, __m256i y) {
    // Ensure the shift counts are within the range of 0 to 7
  __m256i y_mod = _mm256_and_si256(y, _mm256_set1_epi8(7));

  // Left shift x by y_mod
  __m256i left_shift = _mm256_sllv_epi8(x, y_mod);

  // Compute the right shift counts
  __m256i right_shift_counts = _mm256_sub_epi8(_mm256_set1_epi8(8), y_mod);

  // Right shift x by (8 - y_mod)
  __m256i right_shift = _mm256_srlv_epi8(x, right_shift_counts);

  // Combine the left-shifted and right-shifted results using bitwise OR
  __m256i rotated = _mm256_or_si256(left_shift, right_shift);

  return rotated;
}

// Rotates x left by r bits
inline __m256i _mm256_rol_epi8(__m256i x, int r) {
  // Unpack 2 8 bit numbers into their own vectors, and isolate them using masks
  __m256i mask1 = _mm256_set1_epi16(0x00FF);
  __m256i mask2 = _mm256_set1_epi16(0xFF00);
  __m256i a = _mm256_and_si256(x, mask1);
  __m256i b = _mm256_and_si256(x, mask2);

  // Apply the 8bit rotation to the lower 8 bits, then mask out any extra/overflow
  __m256i shiftedA = _mm256_slli_epi16(a, r);
  __m256i wrappedA = _mm256_srli_epi16(a, 8 - r);
  __m256i rotatedA = _mm256_or_si256(shiftedA, wrappedA);
  rotatedA = _mm256_and_si256(rotatedA, mask1);

  // Apply the 8bit rotation to the upper 8 bits, then mask out any extra/overflow
  __m256i shiftedB = _mm256_slli_epi16(b, r);
  __m256i wrappedB = _mm256_srli_epi16(b, 8 - r);
  __m256i rotatedB = _mm256_or_si256(shiftedB, wrappedB);
  rotatedB = _mm256_and_si256(rotatedB, mask2);

  // Re-pack the isolated results into a 16-bit block
  __m256i rotated = _mm256_or_si256(rotatedA, rotatedB);

  return rotated;
}

// parallelPopcnt16bytes- find population count for 8-bit groups in xmm (16 groups)
//                         each unsigned char of xmm result contains a value ranging from 0 to 8
//
inline __m128i parallelPopcnt16bytes(__m128i xmm)
{
  const __m128i mask4 = _mm_set1_epi8 (0x0F);
  const __m128i lookup = _mm_setr_epi8 (0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4);
  __m128i low, high, count;

  low = _mm_and_si128 (mask4, xmm);
  high = _mm_and_si128 (mask4, _mm_srli_epi16 (xmm, 4));
  count = _mm_add_epi8 (_mm_shuffle_epi8 (lookup, low), _mm_shuffle_epi8 (lookup, high));
  return count;
}

inline __m256i popcnt256_epi8(__m256i data) {
  __m128i hi = _mm256_extractf128_si256(data, 1);
  __m128i lo = _mm256_castsi256_si128(data);

  hi = parallelPopcnt16bytes(hi);
  lo = parallelPopcnt16bytes(lo);

  __m256i pop = _mm256_set_m128i(hi,lo);
  return pop;
}

inline int check_results(__m256i avx_result, unsigned char* scalar_result, int num_elements) {
  union {
     __m256i avx;
     unsigned char scalar[32];
  } converter;

  converter.avx = avx_result;

  for(int i = 0; i < num_elements; ++i) {
    if (converter.scalar[i] != scalar_result[i]) {
      std::cout << "Mismatch at index: " << i << std::endl;
      std::cout << "AVX: " << static_cast<int>(converter.scalar[i]) 
                << " Scalar: " << static_cast<int>(scalar_result[i]) << std::endl;
      return 0;
    }
  }

  return 1; 
}

inline __m256i _mm256_reverse_epi8(__m256i input) {
    const __m256i mask_0f = _mm256_set1_epi8(0x0F);
    const __m256i mask_33 = _mm256_set1_epi8(0x33);
    const __m256i mask_55 = _mm256_set1_epi8(0x55);

    // b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
    __m256i temp = _mm256_and_si256(input, mask_0f);
    temp = _mm256_slli_epi16(temp, 4);
    input = _mm256_and_si256(input, _mm256_andnot_si256(mask_0f, _mm256_set1_epi8(0xFF)));
    input = _mm256_srli_epi16(input, 4);
    input = _mm256_or_si256(input, temp);

    // b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
    temp = _mm256_and_si256(input, mask_33);
    temp = _mm256_slli_epi16(temp, 2);
    input = _mm256_and_si256(input, _mm256_andnot_si256(mask_33, _mm256_set1_epi8(0xFF)));
    input = _mm256_srli_epi16(input, 2);
    input = _mm256_or_si256(input, temp);

    // b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
    temp = _mm256_and_si256(input, mask_55);
    temp = _mm256_slli_epi16(temp, 1);
    input = _mm256_and_si256(input, _mm256_andnot_si256(mask_55, _mm256_set1_epi8(0xFF)));
    input = _mm256_srli_epi16(input, 1);
    input = _mm256_or_si256(input, temp);

    return input;
}

uint32_t branchComputeCPU_avx2(RC4_KEY key, unsigned char *sData);
#else
#define ALIGNMENT 16
#endif

#define rl8(x, y) ((x << (y%8) | x >> (8-(y%8))))

inline unsigned char
leftRotate8(unsigned char n, unsigned d)
{ // rotate n by d bits
#if defined(_WIN32)
  return _rotl8(n, d);
#else
  d = d % 8;
  return (n << d) | (n >> (8 - d));
#endif
}

inline unsigned char reverse8(unsigned char b)
{
  return (b * 0x0202020202ULL & 0x010884422010ULL) % 1023;
}

template <typename T>
inline void prefetch(T *data, int size, int hint) {
  const size_t prefetch_distance = 256; // Prefetch 8 cache lines ahead
  const size_t cache_line_size = 64; // Assuming a 64-byte cache line

  //for (size_t i = 0; i < size; i += prefetch_distance * cache_line_size) {
  //    __builtin_prefetch(&data[i], 0, hint);
  //}
  switch(hint) {
    case 0:
      for (size_t i = 0; i < size; i += prefetch_distance * cache_line_size) {
          __builtin_prefetch(&data[i], 0, 0);
      }
    break;
    case 1:
      for (size_t i = 0; i < size; i += prefetch_distance * cache_line_size) {
          __builtin_prefetch(&data[i], 0, 1);
      }
    break;
    case 2:
      for (size_t i = 0; i < size; i += prefetch_distance * cache_line_size) {
          __builtin_prefetch(&data[i], 0, 2);
      }
    break;
    case 3:
      for (size_t i = 0; i < size; i += prefetch_distance * cache_line_size) {
          __builtin_prefetch(&data[i], 0, 3);
      }
      break;
    default:
    break;
  }
}

template <typename T>
inline void insertElement(T* arr, int& size, int capacity, int index, const T& element) {
    if (size < capacity) {
        // Shift elements to the right
        for (int i = size - 1; i >= index; i--) {
            arr[i + 1] = arr[i];
        }

        // Insert the new element
        arr[index] = element;

        // Increase the size
        size++;
    } else {
        std::cout << "Array is full. Cannot insert element." << std::endl;
    }
}

void AstroBWTv3(const unsigned char *input, int inputLen, unsigned char *outputhash);
uint32_t branchComputeCPU(RC4_KEY key, unsigned char *sData);
uint32_t wolfCompute(RC4_KEY key, unsigned char *sData);

#if defined(__aarch64__)
uint32_t branchComputeCPU_aarch64(RC4_KEY key, unsigned char *sData)
#endif

#endif