// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FPDFAPI_RENDER_CPDF_TRANSFERFUNC_H_
#define CORE_FPDFAPI_RENDER_CPDF_TRANSFERFUNC_H_

#include <array>

#include "core/fxcrt/retain_ptr.h"
#include "core/fxcrt/unowned_ptr.h"
#include "core/fxge/fx_dib.h"
#include "third_party/base/span.h"

class CPDF_Document;
class CFX_DIBBase;

class CPDF_TransferFunc final : public Retainable {
 public:
  static constexpr size_t kChannelSampleSize = 256;
  static constexpr size_t kSampleSize = kChannelSampleSize * 3;

  template <typename T, typename... Args>
  friend RetainPtr<T> pdfium::MakeRetain(Args&&... args);

  FX_COLORREF TranslateColor(FX_COLORREF colorref) const;
  RetainPtr<CFX_DIBBase> TranslateImage(const RetainPtr<CFX_DIBBase>& pSrc);

  const CPDF_Document* GetDocument() const { return m_pPDFDoc.Get(); }

  // Spans are |kChannelSampleSize| in size.
  pdfium::span<const uint8_t> GetRSamples() const;
  pdfium::span<const uint8_t> GetGSamples() const;
  pdfium::span<const uint8_t> GetBSamples() const;

  bool GetIdentity() const { return m_bIdentity; }

 private:
  CPDF_TransferFunc(CPDF_Document* pDoc,
                    bool bIdentity,
                    std::array<uint8_t, kSampleSize> samples);
  ~CPDF_TransferFunc() override;

  UnownedPtr<CPDF_Document> const m_pPDFDoc;
  const bool m_bIdentity;
  const std::array<uint8_t, kSampleSize> m_Samples;
  const pdfium::span<const uint8_t> m_SamplesSpan;
};

#endif  // CORE_FPDFAPI_RENDER_CPDF_TRANSFERFUNC_H_
