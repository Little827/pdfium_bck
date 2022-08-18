// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/fx_memory.h"

#include <stdlib.h>  // For abort().

#include <iterator>
#include <limits>

#include "base/allocator/partition_allocator/partition_alloc.h"
#include "build/build_config.h"
#include "core/fxcrt/fx_safe_types.h"
#include "third_party/base/debug/alias.h"
#include "third_party/base/no_destructor.h"

#if BUILDFLAG(IS_WIN)
#include <windows.h>
#endif

// TODO(tsepez): remove if/when PartitionAlloc supports MSVC.
#if !defined(COMPILER_MSVC)
#define FX_MEMORY_USE_PA
#endif

#if defined(FX_MEMORY_USE_PA)
namespace {

constexpr partition_alloc::PartitionOptions kOptions = {
    partition_alloc::PartitionOptions::AlignedAlloc::kDisallowed,
    partition_alloc::PartitionOptions::ThreadCache::kDisabled,
    partition_alloc::PartitionOptions::Quarantine::kDisallowed,
    partition_alloc::PartitionOptions::Cookie::kAllowed,
    partition_alloc::PartitionOptions::BackupRefPtr::kDisabled,
    partition_alloc::PartitionOptions::BackupRefPtrZapping::kDisabled,
    partition_alloc::PartitionOptions::UseConfigurablePool::kNo,
};

partition_alloc::PartitionAllocator& GetArrayBufferPartitionAllocator() {
  static pdfium::base::NoDestructor<partition_alloc::PartitionAllocator>
      s_array_buffer_allocator;
  return *s_array_buffer_allocator;
}

partition_alloc::PartitionAllocator& GetGeneralPartitionAllocator() {
  static pdfium::base::NoDestructor<partition_alloc::PartitionAllocator>
      s_general_allocator;
  return *s_general_allocator;
}

partition_alloc::PartitionAllocator& GetStringPartitionAllocator() {
  static pdfium::base::NoDestructor<partition_alloc::PartitionAllocator>
      s_string_allocator;
  return *s_string_allocator;
}

}  // namespace
#endif  // defined(FX_MEMORY_USE_PA)

void FX_InitializeMemoryAllocators() {
#if defined(FX_MEMORY_USE_PA)
  static bool s_partition_allocators_initialized = false;
  if (!s_partition_allocators_initialized) {
    partition_alloc::PartitionAllocGlobalInit(FX_OutOfMemoryTerminate);
    GetArrayBufferPartitionAllocator().init(kOptions);
    GetGeneralPartitionAllocator().init(kOptions);
    GetStringPartitionAllocator().init(kOptions);
    s_partition_allocators_initialized = true;
  }
#endif  // defined(FX_MEMORY_USE_PA)
}

void* FXMEM_DefaultAlloc(size_t byte_size) {
  return pdfium::internal::Alloc(byte_size, 1);
}

void* FXMEM_DefaultCalloc(size_t num_elems, size_t byte_size) {
  return pdfium::internal::Calloc(num_elems, byte_size);
}

void* FXMEM_DefaultRealloc(void* pointer, size_t new_size) {
  return pdfium::internal::Realloc(pointer, new_size, 1);
}

void FXMEM_DefaultFree(void* pointer) {
  FX_Free(pointer);
}

NOINLINE void FX_OutOfMemoryTerminate(size_t size) {
  // Convince the linker this should not be folded with similar functions using
  // Identical Code Folding.
  static int make_this_function_aliased = 0xbd;
  pdfium::base::debug::Alias(&make_this_function_aliased);

#if BUILDFLAG(IS_WIN)
  // The same custom Windows exception code used in Chromium and Breakpad.
  constexpr DWORD kOomExceptionCode = 0xe0000008;
  ULONG_PTR exception_args[] = {size};
  ::RaiseException(kOomExceptionCode, EXCEPTION_NONCONTINUABLE,
                   std::size(exception_args), exception_args);
#endif

  // Terminate cleanly.
  abort();
}

namespace pdfium {
namespace internal {

void* Alloc(size_t num_members, size_t member_size) {
  FX_SAFE_SIZE_T total = member_size;
  total *= num_members;
  if (!total.IsValid())
    return nullptr;
#if defined(FX_MEMORY_USE_PA)
  return GetGeneralPartitionAllocator().root()->AllocWithFlags(
      partition_alloc::AllocFlags::kReturnNull, total.ValueOrDie(),
      "GeneralPartition");
#else
  return malloc(total.ValueOrDie());
#endif
}

void* AllocOrDie(size_t num_members, size_t member_size) {
  void* result = Alloc(num_members, member_size);
  if (!result)
    FX_OutOfMemoryTerminate(0);  // Never returns.

  return result;
}

void* AllocOrDie2D(size_t w, size_t h, size_t member_size) {
  if (w >= std::numeric_limits<size_t>::max() / h)
    FX_OutOfMemoryTerminate(0);  // Never returns.

  return AllocOrDie(w * h, member_size);
}

void* Calloc(size_t num_members, size_t member_size) {
#if defined(FX_MEMORY_USE_PA)
  FX_SAFE_SIZE_T total = member_size;
  total *= num_members;
  if (!total.IsValid())
    return nullptr;

  return GetGeneralPartitionAllocator().root()->AllocWithFlags(
      partition_alloc::AllocFlags::kReturnNull |
          partition_alloc::AllocFlags::kZeroFill,
      total.ValueOrDie(), "GeneralPartition");
#else
  return calloc(num_members, member_size);
#endif
}

void* Realloc(void* ptr, size_t num_members, size_t member_size) {
  FX_SAFE_SIZE_T size = num_members;
  size *= member_size;
  if (!size.IsValid())
    return nullptr;

#if defined(FX_MEMORY_USE_PA)
  return GetGeneralPartitionAllocator().root()->ReallocWithFlags(
      partition_alloc::AllocFlags::kReturnNull, ptr, size.ValueOrDie(),
      "GeneralPartition");
#else
  return realloc(ptr, size.ValueOrDie());
#endif
}

void* CallocOrDie(size_t num_members, size_t member_size) {
  void* result = Calloc(num_members, member_size);
  if (!result)
    FX_OutOfMemoryTerminate(0);  // Never returns.

  return result;
}

void* CallocOrDie2D(size_t w, size_t h, size_t member_size) {
  if (w >= std::numeric_limits<size_t>::max() / h)
    FX_OutOfMemoryTerminate(0);  // Never returns.

  return CallocOrDie(w * h, member_size);
}

void* ReallocOrDie(void* ptr, size_t num_members, size_t member_size) {
  void* result = Realloc(ptr, num_members, member_size);
  if (!result)
    FX_OutOfMemoryTerminate(0);  // Never returns.

  return result;
}

void* StringAllocOrDie(size_t num_members, size_t member_size) {
  void* result = StringAlloc(num_members, member_size);
  if (!result)
    FX_OutOfMemoryTerminate(0);  // Never returns.

  return result;
}

void* StringAlloc(size_t num_members, size_t member_size) {
  FX_SAFE_SIZE_T total = member_size;
  total *= num_members;
  if (!total.IsValid())
    return nullptr;

#if defined(FX_MEMORY_USE_PA)
  return GetStringPartitionAllocator().root()->AllocWithFlags(
      partition_alloc::AllocFlags::kReturnNull, total.ValueOrDie(),
      "StringPartition");
#else
  return malloc(total.ValueOrDie());
#endif
}

}  // namespace internal
}  // namespace pdfium

void* FX_ArrayBufferAllocate(size_t length) {
#if defined(FX_MEMORY_USE_PA)
  return GetArrayBufferPartitionAllocator().root()->AllocWithFlags(
      partition_alloc::AllocFlags::kZeroFill, length, "FXArrayBuffer");
#else
  void* result = calloc(length, 1);
  if (!result)
    FX_OutOfMemoryTerminate(length);
  return result;
#endif
}

void* FX_ArrayBufferAllocateUninitialized(size_t length) {
#if defined(FX_MEMORY_USE_PA)
  return GetArrayBufferPartitionAllocator().root()->Alloc(length,
                                                          "FXArrayBuffer");
#else
  void* result = malloc(length);
  if (!result)
    FX_OutOfMemoryTerminate(length);
  return result;
#endif
}

void FX_ArrayBufferFree(void* data) {
#if defined(FX_MEMORY_USE_PA)
  GetArrayBufferPartitionAllocator().root()->Free(data);
#else
  free(data);
#endif
}

void FX_Free(void* ptr) {
#if defined(FX_MEMORY_USE_PA)
  // TODO(palmer): Removing this check exposes crashes when PDFium callers
  // attempt to free |nullptr|. Although libc's |free| allows freeing |NULL|, no
  // other Partition Alloc callers need this tolerant behavior. Additionally,
  // checking for |nullptr| adds a branch to |PartitionFree|, and it's nice to
  // not have to have that.
  //
  // So this check is hiding (what I consider to be) bugs, and we should try to
  // fix them. https://bugs.chromium.org/p/pdfium/issues/detail?id=690
  if (ptr)
    partition_alloc::ThreadSafePartitionRoot::Free(ptr);
#else
  free(ptr);
#endif
}
