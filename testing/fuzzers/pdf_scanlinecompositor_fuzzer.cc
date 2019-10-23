// Copyright 2019 The PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <vector>

#include "core/fxge/cfx_cliprgn.h"
#include "core/fxge/dib/cfx_dibitmap.h"
#include "core/fxge/fx_dib.h"
#include "testing/fuzzers/pdfium_fuzzer_util.h"
#include "third_party/base/ptr_util.h"

namespace {

constexpr FXDIB_Format kFormat[] = {
    FXDIB_Invalid, FXDIB_1bppRgb,   FXDIB_8bppRgb,  FXDIB_Rgb,
    FXDIB_Rgb32,   FXDIB_1bppMask,  FXDIB_8bppMask, FXDIB_8bppRgba,
    FXDIB_Rgba,    FXDIB_Argb,      FXDIB_1bppCmyk, FXDIB_8bppCmyk,
    FXDIB_Cmyk,    FXDIB_8bppCmyka, FXDIB_Cmyka};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const size_t kParameterSize = 18;
  if (size < kParameterSize) {
    return 0;
  }

  int width = GetInteger(data);
  int height = GetInteger(data + 4);
  uint32_t argb = GetInteger(data + 8);
  data += 12;

  int blend_mode_count = static_cast<int>(BlendMode::kLast) + 1;
  BlendMode blend_mode = static_cast<BlendMode>(data[0] % (blend_mode_count));
  FXDIB_Format dst_format = kFormat[data[1] % FX_ArraySize(kFormat)];
  FXDIB_Format src_format = kFormat[data[2] % 15];
  bool is_clip = !(data[3] % 2);
  bool is_rgb_byte_order = !(data[4] % 2);
  size -= kParameterSize;
  data += 6;

  auto src_bitmap = pdfium::MakeRetain<CFX_DIBitmap>();
  auto dst_bitmap = pdfium::MakeRetain<CFX_DIBitmap>();
  if (!src_bitmap->Create(width, height, src_format) ||
      !dst_bitmap->Create(width, height, dst_format)) {
    return 0;
  }
  if (!src_bitmap->GetBuffer() || !dst_bitmap->GetBuffer()) {
    return 0;
  }

  std::unique_ptr<CFX_ClipRgn> clip_rgn =
      pdfium::MakeUnique<CFX_ClipRgn>(width, height);
  if (src_bitmap->IsAlphaMask()) {
    dst_bitmap->CompositeMask(0, 0, width, height, src_bitmap, argb, 0, 0,
                              blend_mode, (is_clip ? clip_rgn.get() : nullptr),
                              is_rgb_byte_order);
  } else {
    dst_bitmap->CompositeBitmap(
        0, 0, width, height, src_bitmap, 0, 0, blend_mode,
        (is_clip ? clip_rgn.get() : nullptr), is_rgb_byte_order);
  }
  return 0;
}
