// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXCRT_FX_MEMORY_H_
#define CORE_FXCRT_FX_MEMORY_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// For external C libraries to malloc through PDFium. These may return nullptr.
void* FXMEM_DefaultAlloc(size_t byte_size);
void* FXMEM_DefaultCalloc(size_t num_elems, size_t byte_size);
void* FXMEM_DefaultRealloc(void* pointer, size_t new_size);
void FXMEM_DefaultFree(void* pointer);

#ifdef __cplusplus
}  // extern "C"

#include <limits>
#include <type_traits>
#include <utility>

#include "third_party/base/allocator/partition_allocator/partition_alloc.h"

pdfium::base::PartitionAllocatorGeneric& GetArrayBufferPartitionAllocator();
pdfium::base::PartitionAllocatorGeneric& GetGeneralPartitionAllocator();
pdfium::base::PartitionAllocatorGeneric& GetStringPartitionAllocator();

void FXMEM_InitializePartitionAlloc();
NOINLINE void FX_OutOfMemoryTerminate();

// These never return nullptr, and must return cleared memory.
#define FX_Alloc(type, size) \
  static_cast<type*>(FX_AllocOrDie(size, sizeof(type)))
#define FX_Alloc2D(type, w, h) \
  static_cast<type*>(FX_AllocOrDie2D(w, h, sizeof(type)))
#define FX_Realloc(type, ptr, size) \
  static_cast<type*>(FX_ReallocOrDie(ptr, size, sizeof(type)))

// May return nullptr, but returns cleared memory otherwise.
#define FX_TryAlloc(type, size) \
  static_cast<type*>(FX_SafeAlloc(size, sizeof(type)))
#define FX_TryRealloc(type, ptr, size) \
  static_cast<type*>(FX_SafeRealloc(ptr, size, sizeof(type)))

void* FX_SafeAlloc(size_t num_members, size_t member_size);
void* FX_SafeRealloc(void* ptr, size_t num_members, size_t member_size);
void* FX_AllocOrDie(size_t num_members, size_t member_size);
void* FX_AllocOrDie2D(size_t w, size_t h, size_t member_size);
void* FX_ReallocOrDie(void* ptr, size_t num_members, size_t member_size);
void FX_Free(void* ptr);

// The FX_ArraySize(arr) macro returns the # of elements in an array arr.
// The expression is a compile-time constant, and therefore can be
// used in defining new arrays, for example.  If you use FX_ArraySize on
// a pointer by mistake, you will get a compile-time error.
//
// One caveat is that FX_ArraySize() doesn't accept any array of an
// anonymous type or a type defined inside a function.
#define FX_ArraySize(array) (sizeof(ArraySizeHelper(array)))

// This template function declaration is used in defining FX_ArraySize.
// Note that the function doesn't need an implementation, as we only
// use its type.
template <typename T, size_t N>
char (&ArraySizeHelper(T (&array)[N]))[N];

// Round up to the power-of-two boundary N.
template <int N, typename T>
inline T FxAlignToBoundary(T size) {
  static_assert(N > 0 && (N & (N - 1)) == 0, "Not non-zero power of two");
  return (size + (N - 1)) & ~(N - 1);
}

// Used with std::unique_ptr to FX_Free raw memory.
struct FxFreeDeleter {
  inline void operator()(void* ptr) const { FX_Free(ptr); }
};

// Used with std::vector<> to put purely numeric vectors into
// the same "general" parition used by FX_Alloc(). Otherwise,
// replacing FX_Alloc/FX_Free pairs with std::vector<> may undo
// some of the nice segregation that we get from partition alloc.
template <class T>
struct FxAllocAllocator {
 public:
  static_assert(std::is_arithmetic<T>::value,
                "Only numeric types allowed in this partition");

  using value_type = T;
  using pointer = T*;
  using const_pointer = const T*;
  using reference = T&;
  using const_reference = const T&;
  using size_type = size_t;
  using difference_type = ptrdiff_t;

  template <class U>
  struct rebind {
    using other = FxAllocAllocator<U>;
  };

  FxAllocAllocator() noexcept = default;
  FxAllocAllocator(const FxAllocAllocator& other) noexcept = default;
  ~FxAllocAllocator() = default;

  template <typename U>
  FxAllocAllocator(const FxAllocAllocator<U>& other) noexcept {}

  pointer address(reference x) const noexcept { return &x; }
  const_pointer address(const_reference x) const noexcept { return &x; }
  pointer allocate(size_type n, const void* hint = 0) {
    return static_cast<pointer>(FX_AllocOrDie(n, sizeof(value_type)));
  }
  void deallocate(pointer p, size_type n) { FX_Free(p); }
  size_type max_size() const noexcept {
    return std::numeric_limits<size_type>::max() / sizeof(value_type);
  }

  template <class U, class... Args>
  void construct(U* p, Args&&... args) {
    new (reinterpret_cast<void*>(p)) U(std::forward<Args>(args)...);
  }

  template <class U>
  void destroy(U* p) {
    p->~U();
  }

  // There's no state, so they are all the same,
  bool operator==(const FxAllocAllocator& that) { return true; }
  bool operator!=(const FxAllocAllocator& that) { return false; }
};

#endif  // __cplusplus

#endif  // CORE_FXCRT_FX_MEMORY_H_
