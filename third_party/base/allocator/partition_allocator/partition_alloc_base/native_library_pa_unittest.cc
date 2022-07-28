// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/base/allocator/partition_allocator/partition_alloc_base/native_library.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/base/allocator/partition_allocator/partition_alloc_base/files/file_path.h"

namespace pdfium::base::internal::base {

const FilePath::CharType kDummyLibraryPath[] =
    PA_FILE_PATH_LITERAL("dummy_library");

TEST(PartitionAllocBaseNativeLibraryTest, LoadFailure) {
  NativeLibraryLoadError error;
  EXPECT_FALSE(LoadNativeLibrary(FilePath(kDummyLibraryPath), &error));
  EXPECT_FALSE(error.ToString().empty());
}

// |error| is optional and can be null.
TEST(PartitionAllocBaseNativeLibraryTest, LoadFailureWithNullError) {
  EXPECT_FALSE(LoadNativeLibrary(FilePath(kDummyLibraryPath), nullptr));
}

}  // namespace pdfium::base::internal::base
