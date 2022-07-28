// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/base/allocator/partition_allocator/partition_alloc_base/native_library.h"

namespace pdfium::base::internal::base {

NativeLibrary LoadNativeLibrary(const FilePath& library_path,
                                NativeLibraryLoadError* error) {
  return LoadNativeLibraryWithOptions(library_path, NativeLibraryOptions(),
                                      error);
}

}  // namespace pdfium::base::internal::base
