// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BASE_RAND_UTIL_H_
#define THIRD_PARTY_BASE_RAND_UTIL_H_

#include <stddef.h>
#include <stdint.h>

#include "build/build_config.h"
#include "third_party/base/base_export.h"

namespace pdfium {
namespace base {

// Returns a random number in range [0, UINT64_MAX]. Thread-safe.
BASE_EXPORT uint64_t RandUint64();

// Returns a random number between min and max (inclusive). Thread-safe.
BASE_EXPORT int RandInt(int min, int max);

// Returns a random number in range [0, range).  Thread-safe.
BASE_EXPORT uint64_t RandGenerator(uint64_t range);

// Fills |output_length| bytes of |output| with random data. Thread-safe.
//
// Although implementations are required to use a cryptographically secure
// random number source, code outside of base/ that relies on this should use
// crypto::RandBytes instead to ensure the requirement is easily discoverable.
BASE_EXPORT void RandBytes(void* output, size_t output_length);

#if defined(OS_POSIX)
BASE_EXPORT int GetUrandomFD();
#endif

}  // namespace base
}  // namespace pdfium

#endif  // THIRD_PARTY_BASE_RAND_UTIL_H_
