// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXGE_FX_DIB_H_
#define CORE_FXGE_FX_DIB_H_

#include <tuple>
#include <utility>

#include "core/fxcrt/fx_coordinates.h"
#include "core/fxcrt/widestring.h"

enum class FXDIB_Format : uint16_t {
  kInvalid = 0,
  k1bppRgb = 0x001,
  k8bppRgb = 0x008,
  kRgb = 0x018,
  kRgb32 = 0x020,
  k1bppMask = 0x101,
  k8bppMask = 0x108,
  k8bppRgba = 0x208,
  kRgba = 0x218,
  kArgb = 0x220,
  k1bppCmyk = 0x401,
  k8bppCmyk = 0x408,
  kCmyk = 0x420,
  k8bppCmyka = 0x608,
  kCmyka = 0x620,
};

#define FXDIB_Invalid FXDIB_Format::kInvalid
#define FXDIB_1bppRgb FXDIB_Format::k1bppRgb
#define FXDIB_8bppRgb FXDIB_Format::k8bppRgb
#define FXDIB_Rgb FXDIB_Format::kRgb
#define FXDIB_Rgb32 FXDIB_Format::kRgb32
#define FXDIB_1bppMask FXDIB_Format::k1bppMask
#define FXDIB_8bppMask FXDIB_Format::k8bppMask
#define FXDIB_8bppRgba FXDIB_Format::k8bppRgba
#define FXDIB_Rgba FXDIB_Format::kRgba
#define FXDIB_Argb FXDIB_Format::kArgb
#define FXDIB_1bppCmyk FXDIB_Format::k1bppCmyk
#define FXDIB_8bppCmyk FXDIB_Format::k8bppCmyk
#define FXDIB_Cmyk FXDIB_Format::kCmyk
#define FXDIB_8bppCmyka FXDIB_Format::k8bppCmyka
#define FXDIB_Cmyka FXDIB_Format::kCmyka

struct PixelWeight {
  int m_SrcStart;
  int m_SrcEnd;
  int m_Weights[1];
};

using FX_ARGB = uint32_t;

// FX_COLORREF, like win32 COLORREF, is BGR.
using FX_COLORREF = uint32_t;

using FX_CMYK = uint32_t;

extern const int16_t SDP_Table[513];

struct FXDIB_ResampleOptions {
  FXDIB_ResampleOptions();

  bool HasAnyOptions() const;

  bool bInterpolateBilinear = false;
  bool bInterpolateBicubic = false;
  bool bHalftone = false;
  bool bNoSmoothing = false;
  bool bLossy = false;
};

// See PDF 1.7 spec, table 7.2 and 7.3. The enum values need to be in the same
// order as listed in the spec.
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
  kLast = kLuminosity,
};

constexpr uint32_t FXSYS_BGR(uint8_t b, uint8_t g, uint8_t r) {
  return (b << 16) | (g << 8) | r;
}

constexpr uint8_t FXSYS_GetRValue(uint32_t bgr) {
  return bgr & 0xff;
}

constexpr uint8_t FXSYS_GetGValue(uint32_t bgr) {
  return (bgr >> 8) & 0xff;
}

constexpr uint8_t FXSYS_GetBValue(uint32_t bgr) {
  return (bgr >> 16) & 0xff;
}

constexpr unsigned int FXSYS_GetUnsignedAlpha(float alpha) {
  return static_cast<unsigned int>(alpha * 255.f + 0.5f);
}

#define FXSYS_GetCValue(cmyk) ((uint8_t)((cmyk) >> 24) & 0xff)
#define FXSYS_GetMValue(cmyk) ((uint8_t)((cmyk) >> 16) & 0xff)
#define FXSYS_GetYValue(cmyk) ((uint8_t)((cmyk) >> 8) & 0xff)
#define FXSYS_GetKValue(cmyk) ((uint8_t)(cmyk)&0xff)

// Bits per pixel, not bytes.
inline int GetBppFromFormat(FXDIB_Format format) {
  return static_cast<uint16_t>(format) & 0xff;
}

// AKA bytes per pixel, assuming 8-bits per component.
inline int GetCompsFromFormat(FXDIB_Format format) {
  return (static_cast<uint16_t>(format) & 0xff) / 8;
}

inline uint32_t GetAlphaFlagFromFormat(FXDIB_Format format) {
  return (static_cast<uint16_t>(format) >> 8) & 0xff;
}

inline bool GetIsAlphaFromFormat(FXDIB_Format format) {
  return static_cast<uint16_t>(format) & 0x200;
}

inline bool GetIsCmykFromFormat(FXDIB_Format format) {
  return static_cast<uint16_t>(format) & 0x400;
}

inline FXDIB_Format AddAlphaToFormat(FXDIB_Format format) {
  return static_cast<FXDIB_Format>(static_cast<uint16_t>(format) | 0x200);
}

inline FXDIB_Format MakeRGBFormat(int bpp) {
  switch (bpp) {
    case 1:
      return FXDIB_Format::k1bppRgb;
    case 8:
      return FXDIB_Format::k8bppRgb;
    case 24:
      return FXDIB_Format::kRgb;
    case 32:
      return FXDIB_Format::kRgb32;
    default:
      return FXDIB_Format::kInvalid;
  }
}

inline FXDIB_Format MakeARGBFormat(int bpp) {
  switch (bpp) {
    case 8:
      return FXDIB_Format::k8bppRgba;
    case 24:
      return FXDIB_Format::kRgba;
    case 32:
      return FXDIB_Format::kArgb;
    default:
      return FXDIB_Format::kInvalid;
  }
}

inline FXDIB_Format MakeXRGBFormat(bool alpha, int bpp) {
  return alpha ? MakeARGBFormat(bpp) : MakeRGBFormat(bpp);
}

inline FX_CMYK CmykEncode(int c, int m, int y, int k) {
  return (c << 24) | (m << 16) | (y << 8) | k;
}

// Returns (a, r, g, b)
std::tuple<int, int, int, int> ArgbDecode(FX_ARGB argb);

// Returns (a, FX_COLORREF)
std::pair<int, FX_COLORREF> ArgbToAlphaAndColorRef(FX_ARGB argb);

// Returns FX_COLORREF.
FX_COLORREF ArgbToColorRef(FX_ARGB argb);

constexpr FX_ARGB ArgbEncode(int a, int r, int g, int b) {
  return (a << 24) | (r << 16) | (g << 8) | b;
}

FX_ARGB AlphaAndColorRefToArgb(int a, FX_COLORREF colorref);

FX_ARGB StringToFXARGB(WideStringView view);

#define FXARGB_A(argb) ((uint8_t)((argb) >> 24))
#define FXARGB_R(argb) ((uint8_t)((argb) >> 16))
#define FXARGB_G(argb) ((uint8_t)((argb) >> 8))
#define FXARGB_B(argb) ((uint8_t)(argb))
#define FXARGB_MUL_ALPHA(argb, alpha) \
  (((((argb) >> 24) * (alpha) / 255) << 24) | ((argb)&0xffffff))

#define FXRGB2GRAY(r, g, b) (((b)*11 + (g)*59 + (r)*30) / 100)
#define FXDIB_ALPHA_MERGE(backdrop, source, source_alpha) \
  (((backdrop) * (255 - (source_alpha)) + (source) * (source_alpha)) / 255)
#define FXARGB_GETDIB(p)                              \
  ((((uint8_t*)(p))[0]) | (((uint8_t*)(p))[1] << 8) | \
   (((uint8_t*)(p))[2] << 16) | (((uint8_t*)(p))[3] << 24))
#define FXARGB_SETDIB(p, argb)                  \
  ((uint8_t*)(p))[0] = (uint8_t)(argb),         \
  ((uint8_t*)(p))[1] = (uint8_t)((argb) >> 8),  \
  ((uint8_t*)(p))[2] = (uint8_t)((argb) >> 16), \
  ((uint8_t*)(p))[3] = (uint8_t)((argb) >> 24)
#define FXARGB_SETRGBORDERDIB(p, argb)          \
  ((uint8_t*)(p))[3] = (uint8_t)(argb >> 24),   \
  ((uint8_t*)(p))[0] = (uint8_t)((argb) >> 16), \
  ((uint8_t*)(p))[1] = (uint8_t)((argb) >> 8),  \
  ((uint8_t*)(p))[2] = (uint8_t)(argb)
#define FXCMYK_TODIB(cmyk)                                    \
  ((uint8_t)((cmyk) >> 24) | ((uint8_t)((cmyk) >> 16)) << 8 | \
   ((uint8_t)((cmyk) >> 8)) << 16 | ((uint8_t)(cmyk) << 24))
#define FXARGB_TOBGRORDERDIB(argb)                       \
  ((uint8_t)(argb >> 16) | ((uint8_t)(argb >> 8)) << 8 | \
   ((uint8_t)(argb)) << 16 | ((uint8_t)(argb >> 24) << 24))

FX_RECT FXDIB_SwapClipBox(const FX_RECT& clip,
                          int width,
                          int height,
                          bool bFlipX,
                          bool bFlipY);

inline void ReverseCopy3Bytes(uint8_t* dest, const uint8_t* src) {
  dest[2] = src[0];
  dest[1] = src[1];
  dest[0] = src[2];
}

#endif  // CORE_FXGE_FX_DIB_H_
