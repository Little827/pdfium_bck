// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXGE_CFX_DEFAULTRENDERDEVICE_H_
#define CORE_FXGE_CFX_DEFAULTRENDERDEVICE_H_

#include "core/fxcrt/retain_ptr.h"
#include "core/fxge/cfx_renderdevice.h"
#include "core/fxge/dib/fx_dib.h"

class SkPictureRecorder;

class CFX_DefaultRenderDevice final : public CFX_RenderDevice {
 public:
  CFX_DefaultRenderDevice();
  ~CFX_DefaultRenderDevice() override;

  bool Attach(const RetainPtr<CFX_DIBitmap>& pBitmap,
              bool bRgbByteOrder,
              const RetainPtr<CFX_DIBitmap>& pBackdropBitmap,
              bool bGroupKnockout);
  bool Create(int width,
              int height,
              FXDIB_Format format,
              const RetainPtr<CFX_DIBitmap>& pBackdropBitmap);

#if defined(_SKIA_SUPPORT_)
  bool AttachRecorder(SkPictureRecorder* recorder);
  void Clear(uint32_t color);
  SkPictureRecorder* CreateRecorder(int size_x, int size_y);
  void DebugVerifyBitmapIsPreMultiplied() const override;
  bool SetBitsWithMask(const RetainPtr<CFX_DIBBase>& pBitmap,
                       const RetainPtr<CFX_DIBBase>& pMask,
                       int left,
                       int top,
                       int bitmap_alpha,
                       BlendMode blend_type) override;
#endif

#if defined(_AGG_SUPPORT_) && \
    (defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_))
  static bool SkiaIsDefaultRenderer();

  // Update default renderer.  `use_skia` is true for Skia, false for AGG.
  static void SetDefaultRenderer(bool use_skia);
#elif defined(_AGG_SUPPORT_)
  static bool SkiaIsDefaultRenderer() { return false; }
#else
  static bool SkiaIsDefaultRenderer() { return true; }
#endif

 private:
#if defined(_AGG_SUPPORT_)
  bool AttachAgg(const RetainPtr<CFX_DIBitmap>& pBitmap,
                 bool bRgbByteOrder,
                 const RetainPtr<CFX_DIBitmap>& pBackdropBitmap,
                 bool bGroupKnockout);

  bool CreateAgg(int width,
                 int height,
                 FXDIB_Format format,
                 const RetainPtr<CFX_DIBitmap>& pBackdropBitmap);
#endif

#if defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_)
  bool AttachSkia(const RetainPtr<CFX_DIBitmap>& pBitmap,
                  bool bRgbByteOrder,
                  const RetainPtr<CFX_DIBitmap>& pBackdropBitmap,
                  bool bGroupKnockout);

  bool CreateSkia(int width,
                  int height,
                  FXDIB_Format format,
                  const RetainPtr<CFX_DIBitmap>& pBackdropBitmap);
#endif
};

#endif  // CORE_FXGE_CFX_DEFAULTRENDERDEVICE_H_
