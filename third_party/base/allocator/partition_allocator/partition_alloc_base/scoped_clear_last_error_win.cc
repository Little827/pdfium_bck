// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/base/allocator/partition_allocator/partition_alloc_base/scoped_clear_last_error.h"

#include <windows.h>

namespace pdfium::base::internal::base {

ScopedClearLastError::ScopedClearLastError()
    : ScopedClearLastErrorBase(), last_system_error_(GetLastError()) {
  SetLastError(0);
}

ScopedClearLastError::~ScopedClearLastError() {
  SetLastError(last_system_error_);
}

}  // namespace pdfium::base::internal::base
