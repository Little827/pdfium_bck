// Copyright 2022 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/fx_memory.h"

#include "core/fxcrt/fx_safe_types.h"
#include "partition_alloc/partition_alloc.h"

#if !defined(PDF_USE_PARTITION_ALLOC)
#error "File compiled under wrong build option."
#endif

namespace {

constexpr partition_alloc::PartitionOptions kOptions = {};

#ifndef V8_ENABLE_SANDBOX
partition_alloc::PartitionAllocator* g_array_buffer_allocator = nullptr;
#endif

partition_alloc::PartitionAllocator* g_general_allocator = nullptr;
partition_alloc::PartitionAllocator* g_string_allocator = nullptr;

#ifndef V8_ENABLE_SANDBOX
partition_alloc::PartitionAllocator& GetArrayBufferPartitionAllocator() {
  return *g_array_buffer_allocator;
}
#endif

partition_alloc::PartitionAllocator& GetGeneralPartitionAllocator() {
  return *g_general_allocator;
}

partition_alloc::PartitionAllocator& GetStringPartitionAllocator() {
  return *g_string_allocator;
}

}  // namespace

namespace pdfium::internal {

void* Alloc(size_t num_members, size_t member_size) {
  FX_SAFE_SIZE_T total = member_size;
  total *= num_members;
  if (!total.IsValid())
    return nullptr;

  return GetGeneralPartitionAllocator()
      .root()
      ->AllocInline<partition_alloc::AllocFlags::kReturnNull>(
          total.ValueOrDie(), "GeneralPartition");
}

void* Calloc(size_t num_members, size_t member_size) {
  FX_SAFE_SIZE_T total = member_size;
  total *= num_members;
  if (!total.IsValid())
    return nullptr;

  return GetGeneralPartitionAllocator()
      .root()
      ->AllocInline<partition_alloc::AllocFlags::kReturnNull |
                    partition_alloc::AllocFlags::kZeroFill>(total.ValueOrDie(),
                                                            "GeneralPartition");
}

void* Realloc(void* ptr, size_t num_members, size_t member_size) {
  FX_SAFE_SIZE_T size = num_members;
  size *= member_size;
  if (!size.IsValid())
    return nullptr;

  return GetGeneralPartitionAllocator()
      .root()
      ->Realloc<partition_alloc::AllocFlags::kReturnNull>(
          ptr, size.ValueOrDie(), "GeneralPartition");
}

void Dealloc(void* ptr) {
  // TODO(palmer): Removing this check exposes crashes when PDFium callers
  // attempt to free |nullptr|. Although libc's |free| allows freeing |NULL|, no
  // other Partition Alloc callers need this tolerant behavior. Additionally,
  // checking for |nullptr| adds a branch to |PartitionFree|, and it's nice to
  // not have to have that.
  //
  // So this check is hiding (what I consider to be) bugs, and we should try to
  // fix them. https://bugs.chromium.org/p/pdfium/issues/detail?id=690
  if (ptr) {
    GetGeneralPartitionAllocator().root()->Free(ptr);
  }
}

void* StringAlloc(size_t num_members, size_t member_size) {
  FX_SAFE_SIZE_T total = member_size;
  total *= num_members;
  if (!total.IsValid())
    return nullptr;

  return GetStringPartitionAllocator()
      .root()
      ->AllocInline<partition_alloc::AllocFlags::kReturnNull>(
          total.ValueOrDie(), "StringPartition");
}

void StringDealloc(void* ptr) {
  // TODO(palmer): Removing this check exposes crashes when PDFium callers
  // attempt to free |nullptr|. Although libc's |free| allows freeing |NULL|, no
  // other Partition Alloc callers need this tolerant behavior. Additionally,
  // checking for |nullptr| adds a branch to |PartitionFree|, and it's nice to
  // not have to have that.
  //
  // So this check is hiding (what I consider to be) bugs, and we should try to
  // fix them. https://bugs.chromium.org/p/pdfium/issues/detail?id=690
  if (ptr) {
    GetStringPartitionAllocator().root()->Free(ptr);
  }
}

}  // namespace pdfium::internal

void FX_InitializeMemoryAllocators() {
  static bool s_partition_allocators_initialized = false;
  if (!s_partition_allocators_initialized) {
    partition_alloc::PartitionAllocGlobalInit(FX_OutOfMemoryTerminate);
#ifndef V8_ENABLE_SANDBOX
    g_array_buffer_allocator =
        new partition_alloc::PartitionAllocator(kOptions);
#endif  // V8_ENABLE_SANDBOX
    g_general_allocator = new partition_alloc::PartitionAllocator(kOptions);
    g_string_allocator = new partition_alloc::PartitionAllocator(kOptions);
    s_partition_allocators_initialized = true;
  }
}

void FX_DestroyMemoryAllocators() {
#ifndef V8_ENABLE_SANDBOX
  delete g_array_buffer_allocator;
  g_array_buffer_allocator = nullptr;
#endif  // V8_ENABLE_SANDBOX
  delete g_general_allocator;
  g_general_allocator = nullptr;
  delete g_string_allocator;
  g_string_allocator = nullptr;
}

#ifndef V8_ENABLE_SANDBOX
void* FX_ArrayBufferAllocate(size_t length) {
  return GetArrayBufferPartitionAllocator()
      .root()
      ->AllocInline<partition_alloc::AllocFlags::kZeroFill>(length,
                                                            "FXArrayBuffer");
}

void* FX_ArrayBufferAllocateUninitialized(size_t length) {
  return GetArrayBufferPartitionAllocator().root()->Alloc(length,
                                                          "FXArrayBuffer");
}

void FX_ArrayBufferFree(void* data) {
  GetArrayBufferPartitionAllocator().root()->Free(data);
}
#endif  // V8_ENABLE_SANDBOX
