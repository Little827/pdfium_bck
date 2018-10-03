// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fpdfapi/render/cpdf_transferfunc.h"

#include <utility>

#include "core/fpdfapi/parser/cpdf_document.h"
#include "core/fpdfapi/render/cpdf_dibtransferfunc.h"
#include "core/fxge/dib/cfx_dibbase.h"

namespace {

constexpr size_t kROffset = 0 * CPDF_TransferFunc::kChannelSampleSize;
constexpr size_t kGOffset = 1 * CPDF_TransferFunc::kChannelSampleSize;
constexpr size_t kBOffset = 2 * CPDF_TransferFunc::kChannelSampleSize;

}  // namespace

CPDF_TransferFunc::CPDF_TransferFunc(CPDF_Document* pDoc,
                                     bool bIdentity,
                                     std::array<uint8_t, kSampleSize> samples)
    : m_pPDFDoc(pDoc),
      m_bIdentity(bIdentity),
      m_Samples(std::move(samples)),
      m_SamplesSpan(m_Samples.data(), m_Samples.size()) {}

CPDF_TransferFunc::~CPDF_TransferFunc() = default;

FX_COLORREF CPDF_TransferFunc::TranslateColor(FX_COLORREF colorref) const {
  return FXSYS_BGR(m_Samples[kBOffset + FXSYS_GetBValue(colorref)],
                   m_Samples[kGOffset + FXSYS_GetGValue(colorref)],
                   m_Samples[kROffset + FXSYS_GetRValue(colorref)]);
}

RetainPtr<CFX_DIBBase> CPDF_TransferFunc::TranslateImage(
    const RetainPtr<CFX_DIBBase>& pSrc) {
  RetainPtr<CPDF_TransferFunc> pHolder(this);
  auto pDest = pdfium::MakeRetain<CPDF_DIBTransferFunc>(pHolder);
  pDest->LoadSrc(pSrc);
  return pDest;
}

pdfium::span<const uint8_t> CPDF_TransferFunc::GetRSamples() const {
  return m_SamplesSpan.subspan(kROffset, kChannelSampleSize);
}

pdfium::span<const uint8_t> CPDF_TransferFunc::GetGSamples() const {
  return m_SamplesSpan.subspan(kGOffset, kChannelSampleSize);
}

pdfium::span<const uint8_t> CPDF_TransferFunc::GetBSamples() const {
  return m_SamplesSpan.subspan(kBOffset, kChannelSampleSize);
}
