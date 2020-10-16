// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXGE_DIB_CFX_SCANLINECOMPOSITOR_H_
#define CORE_FXGE_DIB_CFX_SCANLINECOMPOSITOR_H_

#include <memory>

#include "core/fxcrt/fx_memory_wrappers.h"
#include "core/fxge/fx_dib.h"

class CFX_ScanlineCompositor {
 public:
  CFX_ScanlineCompositor();
  ~CFX_ScanlineCompositor();

  bool Init(FXDIB_Format dest_format,
            FXDIB_Format src_format,
            int32_t width,
            uint32_t* pSrcPalette,
            uint32_t mask_color,
            BlendMode blend_type,
            bool bClip,
            bool bRgbByteOrder);

  void CompositeRgbBitmapLine(uint8_t* dest_scan,
                              const uint8_t* src_scan,
                              int width,
                              const uint8_t* clip_scan,
                              const uint8_t* src_extra_alpha,
                              uint8_t* dst_extra_alpha);

  void CompositePalBitmapLine(uint8_t* dest_scan,
                              const uint8_t* src_scan,
                              int src_left,
                              int width,
                              const uint8_t* clip_scan,
                              const uint8_t* src_extra_alpha,
                              uint8_t* dst_extra_alpha);

  void CompositeByteMaskLine(uint8_t* dest_scan,
                             const uint8_t* src_scan,
                             int width,
                             const uint8_t* clip_scan,
                             uint8_t* dst_extra_alpha);

  void CompositeBitMaskLine(uint8_t* dest_scan,
                            const uint8_t* src_scan,
                            int src_left,
                            int width,
                            const uint8_t* clip_scan,
                            uint8_t* dst_extra_alpha);

 private:
  class Palette {
   public:
    Palette();
    ~Palette();

    void Reset();

    // These two take ownership of |ptr|.
    void Set8BitPalette(uint8_t* ptr);
    void Set32BitPalette(uint32_t* ptr);

    const uint8_t* Get8BitPalette() const;
    const uint32_t* Get32BitPalette() const;

    std::unique_ptr<uint32_t, FxFreeDeleter> m_pData;

    // If 0, then no |m_pData|.
    // If 1, then |m_pData| is really uint8_t* instead.
    // If 4, then |m_pData| is uint32_t* as expected.
    size_t m_Width = 0;
  };

  void InitSourcePalette(FXDIB_Format src_format,
                         FXDIB_Format dest_format,
                         const uint32_t* pSrcPalette);

  void InitSourceMask(uint32_t mask_color);

  int m_iTransparency;
  FXDIB_Format m_SrcFormat;
  FXDIB_Format m_DestFormat;
  Palette m_SrcPalette;
  int m_MaskAlpha;
  int m_MaskRed;
  int m_MaskGreen;
  int m_MaskBlue;
  BlendMode m_BlendType = BlendMode::kNormal;
  bool m_bRgbByteOrder = false;
};

#endif  // CORE_FXGE_DIB_CFX_SCANLINECOMPOSITOR_H_
