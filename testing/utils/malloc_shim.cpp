// Copyright 2023 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <new>

#include "base/allocator/partition_allocator/partition_alloc.h"
#include "build/build_config.h"
#include "third_party/base/no_destructor.h"

#if !defined(PDF_USE_PARTITION_ALLOC)
#error "Malloc shim must use partition alloc."
#endif

namespace {

constexpr partition_alloc::PartitionOptions kOptions = {
    partition_alloc::PartitionOptions::AlignedAlloc::kDisallowed,
    partition_alloc::PartitionOptions::ThreadCache::kDisabled,
    partition_alloc::PartitionOptions::Quarantine::kDisallowed,
    partition_alloc::PartitionOptions::Cookie::kAllowed,
#if BUILDFLAG(ENABLE_BACKUP_REF_PTR_SUPPORT)
    partition_alloc::PartitionOptions::BackupRefPtr::kEnabled,
    partition_alloc::PartitionOptions::BackupRefPtrZapping::kEnabled,
#else
    partition_alloc::PartitionOptions::BackupRefPtr::kDisabled,
    partition_alloc::PartitionOptions::BackupRefPtrZapping::kDisabled,
#endif
    partition_alloc::PartitionOptions::UseConfigurablePool::kNo,
};

partition_alloc::PartitionAllocator& GetBrpPartitionAllocator() {
  static bool s_allocator_initialized = false;
  static pdfium::base::NoDestructor<partition_alloc::PartitionAllocator>
      s_allocator;

  if (!s_allocator_initialized) {
    s_allocator_initialized = true;
    s_allocator->init(kOptions);
  }
  return *s_allocator;
}

void* ShimCppNew(size_t size) {
  return GetBrpPartitionAllocator().root()->AllocWithFlags(0, size,
                                                           "BRP Partition");
}

void* ShimCppNewNoThrow(size_t size) noexcept {
  return GetBrpPartitionAllocator().root()->AllocWithFlags(0, size,
                                                           "BRP Partition");
}

void* ShimCppAlignedNew(size_t size, size_t ignore) {
  return GetBrpPartitionAllocator().root()->AllocWithFlags(0, size,
                                                           "BRP Partition");
}

void ShimCppDelete(void* p) {
  GetBrpPartitionAllocator().root()->Free(p);
}

}  // namespace

void* operator new(size_t size) {
  return ShimCppNew(size);
}

void operator delete(void* p) noexcept {
  ShimCppDelete(p);
}

void* operator new[](size_t size) {
  return ShimCppNew(size);
}

void operator delete[](void* p) {
  ShimCppDelete(p);
}

void* operator new(size_t size, const std::nothrow_t&) noexcept {
  return ShimCppNewNoThrow(size);
}

void* operator new[](size_t size, const std::nothrow_t&) noexcept {
  return ShimCppNewNoThrow(size);
}

void operator delete(void* p, const std::nothrow_t&) noexcept {
  ShimCppDelete(p);
}

void operator delete[](void* p, const std::nothrow_t&) noexcept {
  ShimCppDelete(p);
}

void operator delete(void* p, size_t) noexcept {
  ShimCppDelete(p);
}

void operator delete[](void* p, size_t) noexcept {
  ShimCppDelete(p);
}

void* operator new(std::size_t size, std::align_val_t alignment) {
  return ShimCppAlignedNew(size, static_cast<size_t>(alignment));
}

void* operator new(std::size_t size,
                   std::align_val_t alignment,
                   const std::nothrow_t&) noexcept {
  return ShimCppAlignedNew(size, static_cast<size_t>(alignment));
}

void operator delete(void* p, std::align_val_t) noexcept {
  ShimCppDelete(p);
}

void operator delete(void* p, std::size_t size, std::align_val_t) noexcept {
  ShimCppDelete(p);
}

void operator delete(void* p,
                     std::align_val_t,
                     const std::nothrow_t&) noexcept {
  ShimCppDelete(p);
}

void* operator new[](std::size_t size, std::align_val_t alignment) {
  return ShimCppAlignedNew(size, static_cast<size_t>(alignment));
}

void* operator new[](std::size_t size,
                     std::align_val_t alignment,
                     const std::nothrow_t&) noexcept {
  return ShimCppAlignedNew(size, static_cast<size_t>(alignment));
}

void operator delete[](void* p, std::align_val_t) noexcept {
  ShimCppDelete(p);
}

void operator delete[](void* p, std::size_t size, std::align_val_t) noexcept {
  ShimCppDelete(p);
}

void operator delete[](void* p,
                       std::align_val_t,
                       const std::nothrow_t&) noexcept {
  ShimCppDelete(p);
}
