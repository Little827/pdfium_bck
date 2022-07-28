// Copyright (c) 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BASE_ALLOCATOR_PARTITION_ALLOCATOR_STARSCAN_STACK_STACK_H_
#define THIRD_PARTY_BASE_ALLOCATOR_PARTITION_ALLOCATOR_STARSCAN_STACK_STACK_H_

#include <cstdint>

#include "third_party/base/allocator/partition_allocator/partition_alloc_base/compiler_specific.h"
#include "third_party/base/allocator/partition_allocator/partition_alloc_base/component_export.h"

namespace pdfium::base::internal {

// Returns the current stack pointer.
// TODO(bikineev,1202644): Remove this once base/stack_util.h lands.
PA_COMPONENT_EXPORT(PARTITION_ALLOC) PA_NOINLINE uintptr_t* GetStackPointer();
// Returns the top of the stack using system API.
PA_COMPONENT_EXPORT(PARTITION_ALLOC) void* GetStackTop();

// Interface for stack visitation.
class StackVisitor {
 public:
  virtual void VisitStack(uintptr_t* stack_ptr, uintptr_t* stack_top) = 0;
};

// Abstraction over the stack. Supports handling of:
// - native stack;
// - SafeStack: https://releases.llvm.org/10.0.0/tools/clang/docs/SafeStack.html
class PA_COMPONENT_EXPORT(PARTITION_ALLOC) Stack final {
 public:
  // Sets start of the stack.
  explicit Stack(void* stack_top);

  // Word-aligned iteration of the stack. Flushes callee saved registers and
  // passes the range of the stack on to |visitor|.
  void IteratePointers(StackVisitor* visitor) const;

  // Returns the top of the stack.
  void* stack_top() const { return stack_top_; }

 private:
  void* stack_top_;
};

}  // namespace pdfium::base::internal

#endif  // THIRD_PARTY_BASE_ALLOCATOR_PARTITION_ALLOCATOR_STARSCAN_STACK_STACK_H_
