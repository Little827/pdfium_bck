// Copyright 2014 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fpdfapi/page/cpdf_devicecs.h"

#include <algorithm>

#include "core/fpdfapi/parser/cpdf_array.h"
#include "core/fpdfapi/parser/cpdf_dictionary.h"
#include "core/fpdfapi/parser/cpdf_document.h"
#include "core/fpdfapi/parser/cpdf_stream_acc.h"
#include "core/fpdfapi/parser/cpdf_string.h"
#include "core/fxcodec/fx_codec.h"
#include "core/fxcrt/check.h"
#include "core/fxcrt/notreached.h"
#include "core/fxge/dib/cfx_cmyk_to_srgb.h"

namespace {

float NormalizeChannel(float fVal) {
  return std::clamp(fVal, 0.0f, 1.0f);
}

}  // namespace

CPDF_DeviceCS::CPDF_DeviceCS(Family family) : CPDF_ColorSpace(family) {
  DCHECK(family == Family::kDeviceGray || family == Family::kDeviceRGB ||
         family == Family::kDeviceCMYK);
  SetComponentsForStockCS(ComponentsForFamily(GetFamily()));
}

CPDF_DeviceCS::~CPDF_DeviceCS() = default;

uint32_t CPDF_DeviceCS::v_Load(CPDF_Document* pDoc,
                               const CPDF_Array* pArray,
                               std::set<const CPDF_Object*>* pVisited) {
  // Unlike other classes that inherit from CPDF_ColorSpace, CPDF_DeviceCS is
  // never loaded by CPDF_ColorSpace.
  NOTREACHED_NORETURN();
}

std::optional<std::array<float, 3>> CPDF_DeviceCS::GetRGB(
    pdfium::span<const float> buffer) const {
  switch (GetFamily()) {
    case Family::kDeviceGray: {
      const float v = NormalizeChannel(buffer[0]);
      return std::array<float, 3>{v, v, v};
    }
    case Family::kDeviceRGB: {
      return std::array<float, 3>{NormalizeChannel(buffer[0]),
                                  NormalizeChannel(buffer[1]),
                                  NormalizeChannel(buffer[2])};
    }
    case Family::kDeviceCMYK: {
      if (IsStdConversionEnabled()) {
        const float k = buffer[3];
        return std::array<float, 3>{1.0f - std::min(1.0f, buffer[0] + k),
                                    1.0f - std::min(1.0f, buffer[1] + k),
                                    1.0f - std::min(1.0f, buffer[2] + k)};
      }
      return AdobeCMYK_to_sRGB(
          NormalizeChannel(buffer[0]), NormalizeChannel(buffer[1]),
          NormalizeChannel(buffer[2]), NormalizeChannel(buffer[3]));
    }
    default: {
      NOTREACHED_NORETURN();
    }
  }
}

void CPDF_DeviceCS::TranslateImageLine(pdfium::span<uint8_t> dest_span,
                                       pdfium::span<const uint8_t> src_span,
                                       int pixels,
                                       int image_width,
                                       int image_height,
                                       bool bTransMask) const {
  uint8_t* pDestBuf = dest_span.data();
  const uint8_t* pSrcBuf = src_span.data();
  switch (GetFamily()) {
    case Family::kDeviceGray:
      CHECK(!bTransMask);  // Only applies to CMYK colorspaces.

      for (int i = 0; i < pixels; i++) {
        // Compiler can not conclude that src/dest don't overlap, avoid
        // duplicate loads.
        const uint8_t pix = pSrcBuf[i];
        *pDestBuf++ = pix;
        *pDestBuf++ = pix;
        *pDestBuf++ = pix;
      }
      break;
    case Family::kDeviceRGB:
      CHECK(!bTransMask);  // Only applies to CMYK colorspaces.

      fxcodec::ReverseRGB(pDestBuf, pSrcBuf, pixels);
      break;
    case Family::kDeviceCMYK:
      if (bTransMask) {
        for (int i = 0; i < pixels; i++) {
          // Compiler can't conclude src/dest don't overlap, avoid interleaved
          // loads and stores.
          const uint8_t s0 = pSrcBuf[0];
          const uint8_t s1 = pSrcBuf[1];
          const uint8_t s2 = pSrcBuf[2];
          const int k = 255 - pSrcBuf[3];
          pDestBuf[0] = ((255 - s0) * k) / 255;
          pDestBuf[1] = ((255 - s1) * k) / 255;
          pDestBuf[2] = ((255 - s2) * k) / 255;
          pDestBuf += 3;
          pSrcBuf += 4;
        }
      } else {
        if (IsStdConversionEnabled()) {
          for (int i = 0; i < pixels; i++) {
            // Compiler can't conclude src/dest don't overlap, avoid
            // interleaved loads and stores.
            const uint8_t s0 = pSrcBuf[0];
            const uint8_t s1 = pSrcBuf[1];
            const uint8_t s2 = pSrcBuf[2];
            const uint8_t k = pSrcBuf[3];
            pDestBuf[2] = 255 - std::min(255, s0 + k);
            pDestBuf[1] = 255 - std::min(255, s1 + k);
            pDestBuf[0] = 255 - std::min(255, s2 + k);
            pSrcBuf += 4;
            pDestBuf += 3;
          }
        } else {
          for (int i = 0; i < pixels; i++) {
            std::tie(pDestBuf[2], pDestBuf[1], pDestBuf[0]) =
                AdobeCMYK_to_sRGB1(pSrcBuf[0], pSrcBuf[1], pSrcBuf[2],
                                   pSrcBuf[3]);
            pSrcBuf += 4;
            pDestBuf += 3;
          }
        }
      }
      break;
    default:
      NOTREACHED_NORETURN();
  }
}
