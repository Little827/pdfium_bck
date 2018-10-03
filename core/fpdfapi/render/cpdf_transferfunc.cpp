// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fpdfapi/render/cpdf_transferfunc.h"

#include "core/fpdfapi/parser/cpdf_document.h"
#include "core/fpdfapi/render/cpdf_dibtransferfunc.h"
#include "core/fxge/dib/cfx_dibbase.h"

CPDF_TransferFunc::CPDF_TransferFunc(CPDF_Document* pDoc) : m_pPDFDoc(pDoc) {}

CPDF_TransferFunc::~CPDF_TransferFunc() = default;

FX_COLORREF CPDF_TransferFunc::TranslateColor(FX_COLORREF colorref) const {
  return FXSYS_BGR(m_BSamples[FXSYS_GetBValue(colorref)],
                   m_GSamples[FXSYS_GetGValue(colorref)],
                   m_RSamples[FXSYS_GetRValue(colorref)]);
}

RetainPtr<CFX_DIBBase> CPDF_TransferFunc::TranslateImage(
    const RetainPtr<CFX_DIBBase>& pSrc) {
  RetainPtr<CPDF_TransferFunc> pHolder(this);
  auto pDest = pdfium::MakeRetain<CPDF_DIBTransferFunc>(pHolder);
  pDest->LoadSrc(pSrc);
  return pDest;
}

pdfium::span<const uint8_t> CPDF_TransferFunc::GetRSamples() const {
  return pdfium::make_span(m_RSamples);
}

pdfium::span<const uint8_t> CPDF_TransferFunc::GetGSamples() const {
  return pdfium::make_span(m_GSamples);
}

pdfium::span<const uint8_t> CPDF_TransferFunc::GetBSamples() const {
  return pdfium::make_span(m_BSamples);
}

void CPDF_TransferFunc::SetRSample(size_t index, uint8_t value) {
  ASSERT(index < kSampleSize);
  m_RSamples[index] = value;
}

void CPDF_TransferFunc::SetGSample(size_t index, uint8_t value) {
  ASSERT(index < kSampleSize);
  m_GSamples[index] = value;
}

void CPDF_TransferFunc::SetBSample(size_t index, uint8_t value) {
  ASSERT(index < kSampleSize);
  m_BSamples[index] = value;
}
