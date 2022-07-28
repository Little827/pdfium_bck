// Copyright 2021 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fxjs/cfx_v8_array_buffer_allocator.h"

#include "core/fxcrt/fx_memory.h"
#if BUILD_WITH_CHROMIUM
#include "base/allocator/partition_allocator/partition_alloc.h"
#else
#include "third_party/base/allocator/partition_allocator/partition_alloc.h"
#endif

void* CFX_V8ArrayBufferAllocator::Allocate(size_t length) {
  if (length > kMaxAllowedBytes)
    return nullptr;
#if BUILD_WITH_CHROMIUM
  return GetArrayBufferPartitionAllocator().AllocWithFlags(
      partition_alloc::AllocFlags::kZeroFill, length, "CFX_V8ArrayBuffer");
#else
  return GetArrayBufferPartitionAllocator().root()->AllocFlags(
      pdfium::base::PartitionAllocZeroFill, length, "CFX_V8ArrayBuffer");
#endif
}

void* CFX_V8ArrayBufferAllocator::AllocateUninitialized(size_t length) {
  if (length > kMaxAllowedBytes)
    return nullptr;
#if BUILD_WITH_CHROMIUM
  return GetArrayBufferPartitionAllocator().Alloc(length, "CFX_V8ArrayBuffer");
#else
  return GetArrayBufferPartitionAllocator().root()->Alloc(length,
                                                          "CFX_V8ArrayBuffer");
#endif
}

void CFX_V8ArrayBufferAllocator::Free(void* data, size_t length) {
#if BUILD_WITH_CHROMIUM
  GetArrayBufferPartitionAllocator().Free(data);
#else
  GetArrayBufferPartitionAllocator().root()->Free(data);
#endif
}
