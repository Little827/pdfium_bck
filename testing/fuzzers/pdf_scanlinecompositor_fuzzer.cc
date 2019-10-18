// Copyright 2019 The PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <vector>
#include "core/fxge/cfx_cliprgn.h"
#include "core/fxge/dib/cfx_dibitmap.h"
#include "core/fxge/dib/cfx_scanlinecompositor.h"
#include "core/fxge/dib/scanlinecomposer_iface.h"
#include "core/fxge/fx_dib.h"
#include "testing/fuzzers/pdfium_fuzzer_helper.h"
#include "testing/fuzzers/pdfium_fuzzer_util.h"
#include "third_party/base/ptr_util.h"

namespace {
const FXDIB_Format kFormat[15] = {
    FXDIB_Invalid, FXDIB_1bppRgb,   FXDIB_8bppRgb,  FXDIB_Rgb,
    FXDIB_Rgb32,   FXDIB_1bppMask,  FXDIB_8bppMask, FXDIB_8bppRgba,
    FXDIB_Rgba,    FXDIB_Argb,      FXDIB_1bppCmyk, FXDIB_8bppCmyk,
    FXDIB_Cmyk,    FXDIB_8bppCmyka, FXDIB_Cmyka};

enum class BlendMode {
  kNormal = 0,
  kMultiply,
  kScreen,
  kOverlay,
  kDarken,
  kLighten,
  kColorDodge,
  kColorBurn,
  kHardLight,
  kSoftLight,
  kDifference,
  kExclusion,
  kHue,
  kSaturation,
  kColor,
  kLuminosity,
};
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const size_t kParameterSize = 18;
  if (size < kParameterSize)
    return 0;

  uint32_t width = GetInteger(data);
  uint32_t height = GetInteger(data + 4);
  uint32_t argb = GetInteger(data + 8);
  data += 12;

  BlendMode blend_mode = data[0] % 16;
  FXDIB_Format dest_format = kFormat[data[1] % 15];
  FXDIB_Format src_format = kFormat[data[2] % 15];
  bool b_clip = !(data[3] % 2);
  bool b_rgb_byte_order = !(data[4] % 2);
  size -= kParameterSize;
  data += 6;

  auto bitmap = pdfium::MakeRetain<CFX_DIBitmap>();
  auto dst_bitmap = pdfium::MakeRetain<CFX_DIBitmap>();
  if (!bitmap->Create(width, height, src_format) ||
      !dst_bitmap->Create(width, height, dest_format))
    return 0;
  if (!bitmap || !bitmap->GetBuffer() || !dst_bitmap ||
      !dst_bitmap->GetBuffer())
    return 0;

  std::unique_ptr<CFX_ClipRgn> clip_rgn =
      pdfium::MakeUnique<CFX_ClipRgn>(width, height);
  if (bitmap->IsAlphaMask) {
    dst_bitmap->CompositeMask(0, 0, width, height, bitmap, argb, 0, 0,
                              blend_mode, (b_clip ? clip_rgn.get() : nullptr),
                              b_rgb_byte_order)
  } else {
    dst_bitmap->CompositeBitmap(0, 0, width, height, bitmap, argb, 0, 0,
                                blend_mode, (b_clip ? clip_rgn.get() : nullptr),
                                b_rgb_byte_order);
  }
  return 0;
}
