// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/base/allocator/partition_allocator/partition_alloc_base/rand_util.h"

#include <zircon/syscalls.h>

namespace pdfium::base::internal::base {

void RandBytes(void* output, size_t output_length) {
  zx_cprng_draw(output, output_length);
}

}  // namespace pdfium::base::internal::base
