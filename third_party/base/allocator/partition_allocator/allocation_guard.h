// Copyright 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BASE_ALLOCATOR_PARTITION_ALLOCATOR_ALLOCATION_GUARD_H_
#define THIRD_PARTY_BASE_ALLOCATOR_PARTITION_ALLOCATOR_ALLOCATION_GUARD_H_

#include "build/build_config.h"
#include "third_party/base/allocator/partition_allocator/partition_alloc_base/component_export.h"
#include "third_party/base/allocator/partition_allocator/partition_alloc_config.h"

namespace pdfium::base {

#if defined(PA_HAS_ALLOCATION_GUARD)

// Disallow allocations in the scope. Does not nest.
class PA_COMPONENT_EXPORT(PARTITION_ALLOC) ScopedDisallowAllocations {
 public:
  ScopedDisallowAllocations();
  ~ScopedDisallowAllocations();
};

// Disallow allocations in the scope. Does not nest.
class PA_COMPONENT_EXPORT(PARTITION_ALLOC) ScopedAllowAllocations {
 public:
  ScopedAllowAllocations();
  ~ScopedAllowAllocations();

 private:
  bool saved_value_;
};

#else

struct [[maybe_unused]] ScopedDisallowAllocations {};
struct [[maybe_unused]] ScopedAllowAllocations {};

#endif  // defined(PA_HAS_ALLOCATION_GUARD)

}  // namespace pdfium::base

namespace base::internal {

using ::pdfium::base::ScopedAllowAllocations;
using ::pdfium::base::ScopedDisallowAllocations;

}  // namespace base::internal

#endif  // THIRD_PARTY_BASE_ALLOCATOR_PARTITION_ALLOCATOR_ALLOCATION_GUARD_H_
