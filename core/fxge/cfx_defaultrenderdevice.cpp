// Copyright 2022 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxge/cfx_defaultrenderdevice.h"

#include <memory>

#include "core/fxcrt/retain_ptr.h"
#include "core/fxge/agg/fx_agg_driver.h"
#include "core/fxge/cfx_renderdevice.h"
#include "core/fxge/dib/cfx_dibitmap.h"
#include "core/fxge/dib/fx_dib.h"
#include "core/fxge/skia/fx_skia_device.h"

namespace {

#if defined(_AGG_SUPPORT_) && \
    (defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_))
bool g_default_renderer_is_skia = PDF_DEFAULT_RENDERER_USE_SKIA;
#endif

}  // namespace

#if defined(_AGG_SUPPORT_) && \
    (defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_))
// static
bool CFX_DefaultRenderDevice::SkiaIsDefaultRenderer() {
  return g_default_renderer_is_skia;
}

// static
void CFX_DefaultRenderDevice::SetSkiaAsDefaultRenderer() {
  g_default_renderer_is_skia = true;
}
#endif

CFX_DefaultRenderDevice::CFX_DefaultRenderDevice() = default;

CFX_DefaultRenderDevice::~CFX_DefaultRenderDevice() {
#if defined(_AGG_SUPPORT_) && \
    (defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_))
  if (g_default_renderer_is_skia)
    Flush(true);
#elif defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_)
  Flush(true);
#endif
}

bool CFX_DefaultRenderDevice::CFX_DefaultRenderDevice::Attach(
    const RetainPtr<CFX_DIBitmap>& pBitmap,
    bool bRgbByteOrder,
    const RetainPtr<CFX_DIBitmap>& pBackdropBitmap,
    bool bGroupKnockout) {
#if defined(_AGG_SUPPORT_) && \
    (defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_))
  return g_default_renderer_is_skia
             ? AttachSkia(pBitmap, bRgbByteOrder, pBackdropBitmap,
                          bGroupKnockout)
             : AttachAgg(pBitmap, bRgbByteOrder, pBackdropBitmap,
                         bGroupKnockout);
#elif defined(_AGG_SUPPORT_)
  return AttachAgg(pBitmap, bRgbByteOrder, pBackdropBitmap, bGroupKnockout);
#else
  return AttachSkia(pBitmap, bRgbByteOrder, pBackdropBitmap, bGroupKnockout);
#endif
}

bool CFX_DefaultRenderDevice::Create(
    int width,
    int height,
    FXDIB_Format format,
    const RetainPtr<CFX_DIBitmap>& pBackdropBitmap) {
#if defined(_AGG_SUPPORT_) && \
    (defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_))
  return g_default_renderer_is_skia
             ? CreateSkia(width, height, format, pBackdropBitmap)
             : CreateAgg(width, height, format, pBackdropBitmap);
#elif defined(_AGG_SUPPORT_)
  return CreateAgg(width, height, format, pBackdropBitmap);
#else
  return CreateSkia(width, height, format, pBackdropBitmap);
#endif
}
