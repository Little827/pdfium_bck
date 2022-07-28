// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/base/allocator/partition_allocator/partition_oom.h"

#include "build/build_config.h"
#include "third_party/base/allocator/partition_allocator/oom.h"
#include "third_party/base/allocator/partition_allocator/partition_alloc_base/compiler_specific.h"
#include "third_party/base/allocator/partition_allocator/partition_alloc_base/debug/alias.h"

namespace pdfium::base::internal {

OomFunction g_oom_handling_function = nullptr;

PA_NOINLINE void PA_NOT_TAIL_CALLED
PartitionExcessiveAllocationSize(size_t size) {
  PA_NO_CODE_FOLDING();
  OOM_CRASH(size);
}

#if !defined(ARCH_CPU_64_BITS)
PA_NOINLINE void PA_NOT_TAIL_CALLED
PartitionOutOfMemoryWithLotsOfUncommitedPages(size_t size) {
  PA_NO_CODE_FOLDING();
  OOM_CRASH(size);
}

[[noreturn]] PA_NOINLINE void PA_NOT_TAIL_CALLED
PartitionOutOfMemoryWithLargeVirtualSize(size_t virtual_size) {
  PA_NO_CODE_FOLDING();
  OOM_CRASH(virtual_size);
}

#endif  // !defined(ARCH_CPU_64_BITS)

}  // namespace pdfium::base::internal
