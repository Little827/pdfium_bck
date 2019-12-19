// Copyright 2019 The PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This header defines cross-platform ByteSwap() implementations for 16 and
// 32-bit values.
// Use the functions defined here rather than using the platform-specific
// functions directly.
// This is a modified copy of Chromium's base/sys_byteorder.h.

#ifndef CORE_FXCRT_BYTEORDER_H_
#define CORE_FXCRT_BYTEORDER_H_

#include <stdint.h>

#include "build/build_config.h"

#if defined(COMPILER_MSVC)
#include <stdlib.h>
#endif

namespace fxcrt {

// Returns a value with all bytes in |x| swapped, i.e. reverses the endianness.
inline uint16_t ByteSwap(uint16_t x) {
#if defined(COMPILER_MSVC)
  return _byteswap_ushort(x);
#else
  return __builtin_bswap16(x);
#endif
}

inline uint32_t ByteSwap(uint32_t x) {
#if defined(COMPILER_MSVC)
  return _byteswap_ulong(x);
#else
  return __builtin_bswap32(x);
#endif
}

inline uint64_t ByteSwap(uint64_t x) {
#if defined(COMPILER_MSVC)
  return _byteswap_uint64(x);
#else
  return __builtin_bswap64(x);
#endif
}

// Converts the bytes in |x| from host order (endianness) to little endian, and
// returns the result.
inline uint16_t ByteSwapToLE16(uint16_t x) {
#if defined(ARCH_CPU_LITTLE_ENDIAN)
  return x;
#else
  return ByteSwap(x);
#endif
}

inline uint32_t ByteSwapToLE32(uint32_t x) {
#if defined(ARCH_CPU_LITTLE_ENDIAN)
  return x;
#else
  return ByteSwap(x);
#endif
}

// Converts the bytes in |x| from host order (endianness) to big endian, and
// returns the result.
inline uint16_t ByteSwapToBE16(uint16_t x) {
#if defined(ARCH_CPU_LITTLE_ENDIAN)
  return ByteSwap(x);
#else
  return x;
#endif
}

inline uint32_t ByteSwapToBE32(uint32_t x) {
#if defined(ARCH_CPU_LITTLE_ENDIAN)
  return ByteSwap(x);
#else
  return x;
#endif
}

}  // namespace fxcrt

#endif  // CORE_FXCRT_BYTEORDER_H_
