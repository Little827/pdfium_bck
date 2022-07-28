// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file contains utility functions for dealing with the local
// filesystem.

#ifndef THIRD_PARTY_BASE_ALLOCATOR_PARTITION_ALLOCATOR_PARTITION_ALLOC_BASE_FILES_FILE_UTIL_H_
#define THIRD_PARTY_BASE_ALLOCATOR_PARTITION_ALLOCATOR_PARTITION_ALLOC_BASE_FILES_FILE_UTIL_H_

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "build/build_config.h"
#include "third_party/base/allocator/partition_allocator/partition_alloc_base/component_export.h"

#if BUILDFLAG(IS_POSIX) || BUILDFLAG(IS_FUCHSIA)
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace pdfium::base::internal::base {

#if BUILDFLAG(IS_POSIX) || BUILDFLAG(IS_FUCHSIA)

// Read exactly |bytes| bytes from file descriptor |fd|, storing the result
// in |buffer|. This function is protected against EINTR and partial reads.
// Returns true iff |bytes| bytes have been successfully read from |fd|.
PA_COMPONENT_EXPORT(PARTITION_ALLOC)
bool ReadFromFD(int fd, char* buffer, size_t bytes);

#endif  // BUILDFLAG(IS_POSIX) || BUILDFLAG(IS_FUCHSIA)

}  // namespace pdfium::base::internal::base

#endif  // THIRD_PARTY_BASE_ALLOCATOR_PARTITION_ALLOCATOR_PARTITION_ALLOC_BASE_FILES_FILE_UTIL_H_
