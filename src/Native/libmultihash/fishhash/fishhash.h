#pragma once

#include <cstdint>

#if defined(_MSC_VER)
//  Microsoft
#define EXPORT __declspec(dllexport)
#define IMPORT __declspec(dllimport)
#elif defined(__GNUC__)
//  GCC
#define EXPORT __attribute__((visibility("default")))
#define IMPORT
#else
//  do nothing and hope for the best?
#define EXPORT
#define IMPORT
#pragma warning Unknown dynamic link import / export semantics.
#endif

#ifdef __cplusplus
#define NOEXCEPT noexcept
#else
#define NOEXCEPT
#endif

#ifdef __cplusplus
extern "C" {
#endif

namespace FishHash {

	union fishhash_hash256 {
	    uint64_t word64s[4];
	    uint32_t word32s[8];
	    uint8_t bytes[32];
	    char str[32];
	};

	union fishhash_hash512 {
	    uint64_t word64s[8];
	    uint32_t word32s[16];
	    uint8_t bytes[64];
	    char str[64];
	};

	union fishhash_hash1024 {
	    union fishhash_hash512 hash512s[2];
	    uint64_t word64s[16];
	    uint32_t word32s[32];
	    uint8_t bytes[128];
	    char str[128];
	};


	struct fishhash_context	{
	    const int light_cache_num_items;
	    fishhash_hash512* const light_cache;
	    const int full_dataset_num_items;
	    fishhash_hash1024* full_dataset;
	};
	
	
	EXPORT struct fishhash_context* fishhash_get_context(bool full = false) NOEXCEPT;
	EXPORT void fishhash_prebuild_dataset(fishhash_context * ctx, uint32_t numThreads = 1) NOEXCEPT;
	EXPORT void fishhash_hash(uint8_t * output, const fishhash_context * ctx, const uint8_t * header, uint64_t header_size, uint8_t fishhashkernel = 1) NOEXCEPT;
        EXPORT void fishhaskarlsen_hash(uint8_t * output, const fishhash_context * ctx, const uint8_t * header, uint64_t header_size, uint8_t fishhashkernel = 1) NOEXCEPT;
}

#ifdef __cplusplus
}
#endif

