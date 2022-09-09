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

  bool Attach(RetainPtr<CFX_DIBitmap> pBitmap);
  bool AttachWithRgbByteOrder(RetainPtr<CFX_DIBitmap> pBitmap,
                              bool bRgbByteOrder);
  bool AttachWithBackdropAndGroupKnockout(
      RetainPtr<CFX_DIBitmap> pBitmap,
      RetainPtr<CFX_DIBitmap> pBackdropBitmap,
      bool bGroupKnockout);
  bool Create(int width,
              int height,
              FXDIB_Format format,
              RetainPtr<CFX_DIBitmap> pBackdropBitmap);

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

  // Runtime check to see if Skia is the renderer variant in use.
  static bool SkiaIsDefaultRenderer();

  // Runtime check to see if SkiaPaths is the renderer variant in use.
  static bool SkiaPathsIsDefaultRenderer();

#if defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_)
  // These values need to maintain a 1:1 mapping with the public type
  // `FPDF_RENDERER_TYPE`.
  enum class RendererType {
    kAgg = 0,
#if defined(_SKIA_SUPPORT_)
    kSkia = 1,
#endif
#if defined(_SKIA_SUPPORT_PATHS_)
    kSkiaPaths = 2,
#endif
  };

  // Update default renderer.
  static void SetDefaultRenderer(RendererType renderer_type);
#endif

 private:
  bool AttachImpl(RetainPtr<CFX_DIBitmap> pBitmap,
                  bool bRgbByteOrder,
                  RetainPtr<CFX_DIBitmap> pBackdropBitmap,
                  bool bGroupKnockout);

  bool AttachAggImpl(RetainPtr<CFX_DIBitmap> pBitmap,
                     bool bRgbByteOrder,
                     RetainPtr<CFX_DIBitmap> pBackdropBitmap,
                     bool bGroupKnockout);

  bool CreateAgg(int width,
                 int height,
                 FXDIB_Format format,
                 RetainPtr<CFX_DIBitmap> pBackdropBitmap);

#if defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_)
  bool AttachSkiaImpl(RetainPtr<CFX_DIBitmap> pBitmap,
                      bool bRgbByteOrder,
                      RetainPtr<CFX_DIBitmap> pBackdropBitmap,
                      bool bGroupKnockout);

  bool CreateSkia(int width,
                  int height,
                  FXDIB_Format format,
                  RetainPtr<CFX_DIBitmap> pBackdropBitmap);
#endif
};

#endif  // CORE_FXGE_CFX_DEFAULTRENDERDEVICE_H_
