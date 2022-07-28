// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BASE_ALLOCATOR_PARTITION_ALLOCATOR_PAGE_ALLOCATOR_INTERNAL_H_
#define THIRD_PARTY_BASE_ALLOCATOR_PARTITION_ALLOCATOR_PAGE_ALLOCATOR_INTERNAL_H_

#include <cstddef>
#include <cstdint>

#include "third_party/base/allocator/partition_allocator/page_allocator.h"

namespace pdfium::base::internal {

uintptr_t SystemAllocPages(uintptr_t hint,
                           size_t length,
                           PageAccessibilityConfiguration accessibility,
                           PageTag page_tag);

}  // namespace pdfium::base::internal

#endif  // THIRD_PARTY_BASE_ALLOCATOR_PARTITION_ALLOCATOR_PAGE_ALLOCATOR_INTERNAL_H_
