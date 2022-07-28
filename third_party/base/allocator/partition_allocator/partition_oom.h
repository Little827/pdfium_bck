// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Holds functions for generating OOM errors from PartitionAlloc. This is
// distinct from oom.h in that it is meant only for use in PartitionAlloc.

#ifndef THIRD_PARTY_BASE_ALLOCATOR_PARTITION_ALLOCATOR_PARTITION_OOM_H_
#define THIRD_PARTY_BASE_ALLOCATOR_PARTITION_ALLOCATOR_PARTITION_OOM_H_

#include <stddef.h>

#include "build/build_config.h"
#include "third_party/base/allocator/partition_allocator/partition_alloc_base/compiler_specific.h"
#include "third_party/base/allocator/partition_allocator/partition_alloc_base/component_export.h"

namespace pdfium::base {

using OomFunction = void (*)(size_t);

namespace internal {

// g_oom_handling_function is invoked when PartitionAlloc hits OutOfMemory.
extern OomFunction g_oom_handling_function;

[[noreturn]] PA_COMPONENT_EXPORT(PARTITION_ALLOC) PA_NOINLINE
    void PartitionExcessiveAllocationSize(size_t size);

#if !defined(ARCH_CPU_64_BITS)
[[noreturn]] PA_NOINLINE void PartitionOutOfMemoryWithLotsOfUncommitedPages(
    size_t size);
[[noreturn]] PA_NOINLINE void PartitionOutOfMemoryWithLargeVirtualSize(
    size_t virtual_size);
#endif

}  // namespace internal

}  // namespace pdfium::base

namespace base {

// TODO(https://crbug.com/1288247): Remove these 'using' declarations once
// the migration to the new namespaces gets done.
using ::pdfium::base::OomFunction;

namespace internal {

using ::pdfium::base::internal::g_oom_handling_function;
using ::pdfium::base::internal::PartitionExcessiveAllocationSize;
#if !defined(ARCH_CPU_64_BITS)
using ::pdfium::base::internal::PartitionOutOfMemoryWithLargeVirtualSize;
using ::pdfium::base::internal::PartitionOutOfMemoryWithLotsOfUncommitedPages;
#endif

}  // namespace internal

}  // namespace base

#endif  // THIRD_PARTY_BASE_ALLOCATOR_PARTITION_ALLOCATOR_PARTITION_OOM_H_
