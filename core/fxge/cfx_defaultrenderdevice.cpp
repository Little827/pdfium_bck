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

bool g_default_renderer_is_skia = PDF_DEFAULT_RENDERER_USE_SKIA;

}  // namespace

// static
bool CFX_DefaultRenderDevice::SkiaIsDefaultRenderer() {
  return g_default_renderer_is_skia;
}

// static
void CFX_DefaultRenderDevice::SetSkiaAsDefaultRenderer() {
  g_default_renderer_is_skia = true;
}

CFX_DefaultRenderDevice::CFX_DefaultRenderDevice() = default;

CFX_DefaultRenderDevice::~CFX_DefaultRenderDevice() {
  if (g_default_renderer_is_skia)
    Flush(true);
}

bool CFX_DefaultRenderDevice::CFX_DefaultRenderDevice::Attach(
    const RetainPtr<CFX_DIBitmap>& pBitmap,
    bool bRgbByteOrder,
    const RetainPtr<CFX_DIBitmap>& pBackdropBitmap,
    bool bGroupKnockout) {
  return g_default_renderer_is_skia
             ? AttachSkia(pBitmap, bRgbByteOrder, pBackdropBitmap,
                          bGroupKnockout)
             : AttachAgg(pBitmap, bRgbByteOrder, pBackdropBitmap,
                         bGroupKnockout);
}

bool CFX_DefaultRenderDevice::AttachAgg(
    const RetainPtr<CFX_DIBitmap>& pBitmap,
    bool bRgbByteOrder,
    const RetainPtr<CFX_DIBitmap>& pBackdropBitmap,
    bool bGroupKnockout) {
  if (!pBitmap)
    return false;

  CFX_RenderDevice::SetBitmap(pBitmap);
  CFX_RenderDevice::SetDeviceDriver(
      std::make_unique<pdfium::CFX_AggDeviceDriver>(
          pBitmap, bRgbByteOrder, pBackdropBitmap, bGroupKnockout));
  return true;
}

bool CFX_DefaultRenderDevice::CreateAgg(
    int width,
    int height,
    FXDIB_Format format,
    const RetainPtr<CFX_DIBitmap>& pBackdropBitmap) {
  auto pBitmap = pdfium::MakeRetain<CFX_DIBitmap>();
  if (!pBitmap->Create(width, height, format))
    return false;

  CFX_RenderDevice::SetBitmap(pBitmap);
  CFX_RenderDevice::SetDeviceDriver(
      std::make_unique<pdfium::CFX_AggDeviceDriver>(pBitmap, false,
                                                    pBackdropBitmap, false));
  return true;
}

bool CFX_DefaultRenderDevice::Create(
    int width,
    int height,
    FXDIB_Format format,
    const RetainPtr<CFX_DIBitmap>& pBackdropBitmap) {
  return g_default_renderer_is_skia
             ? CreateSkia(width, height, format, pBackdropBitmap)
             : CreateAgg(width, height, format, pBackdropBitmap);
}

bool CFX_DefaultRenderDevice::AttachSkia(
    const RetainPtr<CFX_DIBitmap>& pBitmap,
    bool bRgbByteOrder,
    const RetainPtr<CFX_DIBitmap>& pBackdropBitmap,
    bool bGroupKnockout) {
  if (!pBitmap)
    return false;
  CFX_RenderDevice::SetBitmap(pBitmap);
  CFX_RenderDevice::SetDeviceDriver(std::make_unique<CFX_SkiaDeviceDriver>(
      pBitmap, bRgbByteOrder, pBackdropBitmap, bGroupKnockout));
  return true;
}

bool CFX_DefaultRenderDevice::CreateSkia(
    int width,
    int height,
    FXDIB_Format format,
    const RetainPtr<CFX_DIBitmap>& pBackdropBitmap) {
  auto pBitmap = pdfium::MakeRetain<CFX_DIBitmap>();
  if (!pBitmap->Create(width, height, format)) {
    return false;
  }
  CFX_RenderDevice::SetBitmap(pBitmap);
  CFX_RenderDevice::SetDeviceDriver(std::make_unique<CFX_SkiaDeviceDriver>(
      pBitmap, false, pBackdropBitmap, false));
  return true;
}
