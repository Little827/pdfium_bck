// Copyright 2020 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/pdf_test_environment.h"

#include "build/build_config.h"
#include "core/fxge/cfx_gemodule.h"

#if defined(PDF_USE_PARTITION_ALLOC)
#include "base/allocator/partition_allocator/partition_alloc_buildflags.h"
#include "base/allocator/partition_allocator/shim/allocator_shim.h"
#endif

PDFTestEnvironment::PDFTestEnvironment() {
#if defined(PDF_USE_PARTITION_ALLOC)
#if BUILDFLAG(USE_PARTITION_ALLOC_AS_MALLOC)
  allocator_shim::ConfigurePartitions(
      allocator_shim::EnableBrp(true),
      allocator_shim::EnableMemoryTagging(false),
      allocator_shim::SplitMainPartition(true),
      allocator_shim::UseDedicatedAlignedPartition(true), 0,
      allocator_shim::AlternateBucketDistribution::kDefault);
#endif  // BUILDFLAG(USE_PARTITION_ALLOC_AS_MALLOC)
#endif  // defined(PDF_USE_PARTITION_ALLOC)
}

PDFTestEnvironment::~PDFTestEnvironment() = default;

// testing::Environment:
void PDFTestEnvironment::SetUp() {
  CFX_GEModule::Create(test_fonts_.font_paths());
}

void PDFTestEnvironment::TearDown() {
  CFX_GEModule::Destroy();
}
