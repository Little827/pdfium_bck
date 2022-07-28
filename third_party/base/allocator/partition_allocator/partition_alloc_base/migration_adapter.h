// Copyright (c) 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BASE_ALLOCATOR_PARTITION_ALLOCATOR_PARTITION_ALLOC_BASE_MIGRATION_ADAPTER_H_
#define THIRD_PARTY_BASE_ALLOCATOR_PARTITION_ALLOCATOR_PARTITION_ALLOC_BASE_MIGRATION_ADAPTER_H_

namespace base {

class LapTimer;

}  // namespace base

namespace pdfium::base::internal::base {

// TODO(https://crbug.com/1288247): Remove these 'using' declarations once
// the migration to the new namespaces gets done.
using ::base::LapTimer;

}  // namespace pdfium::base::internal::base

#endif  // THIRD_PARTY_BASE_ALLOCATOR_PARTITION_ALLOCATOR_PARTITION_ALLOC_BASE_MIGRATION_ADAPTER_H_
