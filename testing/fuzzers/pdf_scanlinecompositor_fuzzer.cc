// Copyright 2019 The PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <vector>
#include "core/fxge/dib/cfx_scanlinecompositor.h"
#include "core/fxge/dib/scanlinecomposer_iface.h"
#include "third_party/base/span.h"
/*
struct Params {
  bool delete_backwards;
  uint8_t count;
};

Params GetParams(FuzzedDataProvider* data_provider) {
  Params params;
  params.delete_backwards = data_provider->ConsumeBool();
  params.count = data_provider->ConsumeIntegralInRange(1, 255);
  return params;
}

std::vector<WideString> GetNames(uint8_t count,
                                 FuzzedDataProvider* data_provider) {
  std::vector<WideString> names;
  names.reserve(count);
  for (size_t i = 0; i < count; ++i) {
    // The name is not that interesting here. Keep it short.
    constexpr size_t kMaxNameLen = 10;
    std::string str = data_provider->ConsumeRandomLengthString(kMaxNameLen);
    names.push_back(WideString::FromUTF16LE(
        reinterpret_cast<const unsigned short*>(str.data()),
        str.size() / sizeof(unsigned short)));
  }
  return names;
}
*/
namespace {
const FXDIB_Format kFormat[15] = {FXDIB_Invalid,  FXDIB_1bppRgb,
                                  FXDIB_8bppRgb,  FXDIB_Rgb,
                                  FXDIB_Rgb32,    FXDIB_1bppMask,
                                  FXDIB_8bppMask, FXDIB_8bppRgba,
                                  FXDIB_Rgba,     FXDIB_Argb,
                                  FXDIB_1bppCmyk, FXDIB_8bppCmyk,
                                  FXDIB_Cmyk,     FXDIB_8bppCmyka FXDIB_Cmyka};

const BlendMode kBlendMode[16] = {
    kNormal,     kMultiply,   kScreen,    kOverlay,   kDarken,     kLighten,
    kColorDodge, kColorBurn,  kHardLight, kSoftLight, kDifference, kExclusion,
    kHue,        kSaturation, kColor,     kLuminosity};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider data_provider(data, size);
  if (size < 16)
    return 0;
  uint32_t width = GetInteger(data);
  uint32_t height = GetInteger(data + 4);
  data += 8;

  uint8_t test_selector = data[0] % 10;
  BlendMode blend_mode = kBlendMode[data[1] % 16];
  FXDIB_Format dest_format = kFormat[data[2] % 15];
  FXDIB_Format src_format = kFormat[data[3] % 15];
  bool b_clip = !(data[4] % 2);
  bool b_rgb_byte_order = !(data[5] % 2);

  size -= 16;
  data += 8;

  auto bitmap = pdfium::MakeRetain<CFX_DIBitmap>();
  if (!bitmap->Create(width, height, FXDIB_1bppRgb))
    return 0;
  uint32_t* src_palette = bitmap->GetPalette();
  /*
  Params params = GetParams(&data_provider);
  std::vector<WideString> names = GetNames(params.count, &data_provider);
    */
  CFX_ScanlineCompositor scanline_compositor;  // = CFX_ScanlineCompositor();
  scanline_compositor.Init(dest_format, src_format, width, &src_palette,
                           mask_color, blend_mode, b_clip, bRgbByteOrder);

  switch (test_selector) {
    case 0:
      scanline_compositor.InitSourceMask(mask_color);
      break;
    case 1:
      scanline_compositor.CompositeRgbBitmapLine();
      break;
    case 2:
      scanline_compositor.CompositeByteMaskLine();
      break;
    case 3:
      scanline_compositor.CompositePalBitmapLine();
      break;
    case 4:
      scanline_compositor.CompositeBitMaskLine();
      break;
  }

  return 0;
}
