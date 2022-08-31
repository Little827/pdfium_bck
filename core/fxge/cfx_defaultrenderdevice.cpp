// Copyright 2022 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxge/cfx_defaultrenderdevice.h"

#include <utility>

#include "core/fxge/dib/cfx_dibitmap.h"

#if defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_)
#include "third_party/base/notreached.h"
#endif

namespace {

// When a Skia build variant is defined then it is assumed as the default.
#if defined(_SKIA_SUPPORT_)
FPDF_RENDERER_TYPE g_default_renderer_type = FPDF_RENDERERTYPE_SKIA;
#elif defined(_SKIA_SUPPORT_PATHS_)
FPDF_RENDERER_TYPE g_default_renderer_type = FPDF_RENDERERTYPE_SKIAPATHS;
#endif

#if defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_)
bool IsSkiaVariant() {
#if defined(_SKIA_SUPPORT_)
  return g_default_renderer_type == FPDF_RENDERERTYPE_SKIA;
#endif
#if defined(_SKIA_SUPPORT_PATHS_)
  return g_default_renderer_type == FPDF_RENDERERTYPE_SKIAPATHS;
#endif
}
#endif  // defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_)

}  // namespace

// static
bool CFX_DefaultRenderDevice::SkiaIsDefaultRenderer() {
#if defined(_SKIA_SUPPORT_)
  return g_default_renderer_type == FPDF_RENDERERTYPE_SKIA;
#else
  return false;
#endif
}

// static
bool CFX_DefaultRenderDevice::SkiaPathsIsDefaultRenderer() {
#if defined(_SKIA_SUPPORT_PATHS_)
  return g_default_renderer_type == FPDF_RENDERERTYPE_SKIAPATHS;
#else
  return false;
#endif
}

#if defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_)
// static
void CFX_DefaultRenderDevice::SetDefaultRenderer(
    FPDF_RENDERER_TYPE renderer_type) {
  switch (renderer_type) {
    case FPDF_RENDERERTYPE_AGG:
#if defined(_SKIA_SUPPORT_)
    case FPDF_RENDERERTYPE_SKIA:
#endif
#if defined(_SKIA_SUPPORT_PATHS_)
    case FPDF_RENDERERTYPE_SKIAPATHS:
#endif
      g_default_renderer_type = renderer_type;
      break;
    default:
      // Invalid option.
      NOTREACHED();
      break;
  }
}
#endif

CFX_DefaultRenderDevice::CFX_DefaultRenderDevice() = default;

CFX_DefaultRenderDevice::~CFX_DefaultRenderDevice() {
#if defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_)
  if (CFX_DefaultRenderDevice::SkiaIsDefaultRenderer() ||
      CFX_DefaultRenderDevice::SkiaPathsIsDefaultRenderer()) {
    Flush(true);
  }
#endif
}

bool CFX_DefaultRenderDevice::Attach(RetainPtr<CFX_DIBitmap> pBitmap) {
  return AttachWithRgbByteOrder(std::move(pBitmap), false);
}

bool CFX_DefaultRenderDevice::AttachWithRgbByteOrder(
    RetainPtr<CFX_DIBitmap> pBitmap,
    bool bRgbByteOrder) {
  return AttachImpl(std::move(pBitmap), bRgbByteOrder, nullptr, false);
}

bool CFX_DefaultRenderDevice::AttachWithBackdropAndGroupKnockout(
    RetainPtr<CFX_DIBitmap> pBitmap,
    RetainPtr<CFX_DIBitmap> pBackdropBitmap,
    bool bGroupKnockout) {
  return AttachImpl(std::move(pBitmap), false, std::move(pBackdropBitmap),
                    bGroupKnockout);
}

bool CFX_DefaultRenderDevice::CFX_DefaultRenderDevice::AttachImpl(
    RetainPtr<CFX_DIBitmap> pBitmap,
    bool bRgbByteOrder,
    RetainPtr<CFX_DIBitmap> pBackdropBitmap,
    bool bGroupKnockout) {
#if defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_)
  if (IsSkiaVariant()) {
    return AttachSkiaImpl(pBitmap, bRgbByteOrder, pBackdropBitmap,
                          bGroupKnockout);
  }
#endif
  return AttachAggImpl(pBitmap, bRgbByteOrder, pBackdropBitmap, bGroupKnockout);
}

bool CFX_DefaultRenderDevice::Create(int width,
                                     int height,
                                     FXDIB_Format format,
                                     RetainPtr<CFX_DIBitmap> pBackdropBitmap) {
#if defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_)
  if (IsSkiaVariant())
    return CreateSkia(width, height, format, pBackdropBitmap);
#endif
  return CreateAgg(width, height, format, pBackdropBitmap);
}
