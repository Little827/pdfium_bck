// Copyright 2020 The PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/embedder_test_constants.h"

#include "build/build_config.h"
#include "core/fxge/cfx_defaultrenderdevice.h"

namespace pdfium {

const char kAnnotationStampWithApChecksumSkia[] =
    "e4e7dc6446fa763a245e03eb5de6ed28";
#if BUILDFLAG(IS_APPLE)
const char kAnnotationStampWithApChecksumAgg[] =
    "d243b5d64752be0f45b86df7bd2e2708";
#else
const char kAnnotationStampWithApChecksumAgg[] =
    "cdde6c161679ab10b07c38c1ef04b7e8";
#endif

const char* AnnotationStampWithApChecksum() {
  return CFX_DefaultRenderDevice::SkiaIsDefaultRenderer()
             ? kAnnotationStampWithApChecksumSkia
             : kAnnotationStampWithApChecksumAgg;
}

const char kBlankPage612By792Checksum[] = "1940568c9ba33bac5d0b1ee9558c76b3";

const char kBug890322ChecksumSkia[] = "793689536cf64fe792c2f241888c0cf3";
const char kBug890322ChecksumAgg[] = "6c674642154408e877d88c6c082d67e9";

const char* Bug890322Checksum() {
  return CFX_DefaultRenderDevice::SkiaIsDefaultRenderer()
             ? kBug890322ChecksumSkia
             : kBug890322ChecksumAgg;
}

const char kHelloWorldChecksumSkia[] = "fea3e59b7ac7b7a6940018497034f6cf";
#if BUILDFLAG(IS_APPLE)
const char kHelloWorldChecksumAgg[] = "6eef7237f7591f07616e238422086737";
#else
const char kHelloWorldChecksumAgg[] = "c1c548442e0e0f949c5550d89bf8ae3b";
#endif

const char* HelloWorldChecksum() {
  return CFX_DefaultRenderDevice::SkiaIsDefaultRenderer()
             ? kHelloWorldChecksumSkia
             : kHelloWorldChecksumAgg;
}

const char kHelloWorldRemovedChecksumSkia[] =
    "e51fe51cc5f03ad66f603030df9b0400";
#if BUILDFLAG(IS_APPLE)
const char kHelloWorldRemovedChecksumAgg[] = "6e1cae48a2e35c521dee4ca502f48af6";
#else
const char kHelloWorldRemovedChecksumAgg[] = "4a9b80f675f7f3bf2da1b02f12449e4b";
#endif

const char* HelloWorldRemovedChecksum() {
  return CFX_DefaultRenderDevice::SkiaIsDefaultRenderer()
             ? kHelloWorldRemovedChecksumSkia
             : kHelloWorldRemovedChecksumAgg;
}

const char kManyRectanglesChecksumSkia[] = "4e7e280c1597222afcb0ee3bb90ec119";
const char kRectanglesChecksumSkia[] = "b4e411a6b5ffa59a50efede2efece597";
const char kManyRectanglesChecksumAgg[] = "b0170c575b65ecb93ebafada0ff0f038";
const char kRectanglesChecksumAgg[] = "0a90de37f52127619c3dfb642b5fa2fe";

const char* ManyRectanglesChecksum() {
  return CFX_DefaultRenderDevice::SkiaIsDefaultRenderer()
             ? kManyRectanglesChecksumSkia
             : kManyRectanglesChecksumAgg;
}
const char* RectanglesChecksum() {
  return CFX_DefaultRenderDevice::SkiaIsDefaultRenderer()
             ? kRectanglesChecksumSkia
             : kRectanglesChecksumAgg;
}

const char kTextFormChecksumSkia[] = "f8f0817b19ef07d0404caf008964b7f2";
#if BUILDFLAG(IS_APPLE)
const char kTextFormChecksumAgg[] = "fa2bf756942a950101fc147fc4ef3f82";
#else
const char kTextFormChecksumAgg[] = "6f86fe1dbed5965d91aec6e0b829e29f";
#endif

const char* TextFormChecksum() {
  return CFX_DefaultRenderDevice::SkiaIsDefaultRenderer()
             ? kTextFormChecksumSkia
             : kTextFormChecksumAgg;
}

}  // namespace pdfium
