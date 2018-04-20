// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fpdfapi/page/cpdf_color.h"

#include <iostream>

#include "core/fpdfapi/page/cpdf_docpagedata.h"
#include "core/fpdfapi/parser/cpdf_array.h"
#include "core/fpdfapi/parser/cpdf_document.h"
#include "core/fxcrt/fx_system.h"

CPDF_Color::CPDF_Color() {}

CPDF_Color::~CPDF_Color() {
  ReleaseBuffer();
  ReleaseColorSpace();
}

bool CPDF_Color::IsPattern() const {
  return m_pCS && IsPatternInternal();
}

void CPDF_Color::ReleaseBuffer() {
  std::cerr << (void*)this << " ReleaseBuffer m_pColorBuffer " << (void*)m_pColorBuffer.get() << std::endl;
  if (!m_pColorBuffer)
    return;

  if (IsPatternInternal()) {
    std::cerr << (void*)this << " ReleaseBuffer it's PatternInternal, use m_pColorBuffer as PatternValue" << std::endl;
    PatternValue* pvalue = static_cast<PatternValue*>(m_pColorBuffer.get());
    CPDF_Pattern* pPattern =
        pvalue->m_pCountedPattern ? pvalue->m_pCountedPattern->get() : nullptr;
    if (pPattern) {
      CPDF_DocPageData* pPageData = pPattern->document()->GetPageData();
      if (pPageData)
        pPageData->ReleasePattern(pPattern->pattern_obj());
    }
  }

  std::cerr << (void*)this << " ReleaseBuffer FX_Free(m_pColorBuffer->m_Comps)" << std::endl;
  FX_Free(m_pColorBuffer->m_Comps);
  std::cerr << (void*)this << " ReleaseBuffer m_pColorBuffer = nullptr" << std::endl;
  m_pColorBuffer = nullptr;
}

void CPDF_Color::ReleaseColorSpace() {
  if (!m_pCS)
    return;

  CPDF_Document* pDoc = m_pCS->GetDocument();
  if (!pDoc)
    return;

  auto* pPageData = pDoc->GetPageData();
  if (pPageData)
    pPageData->ReleaseColorSpace(m_pCS->GetArray());

  m_pCS = nullptr;
}

bool CPDF_Color::IsPatternInternal() const {
  return m_pCS->GetFamily() == PDFCS_PATTERN;
}

void CPDF_Color::SetColorSpace(CPDF_ColorSpace* pCS) {
  std::cerr << (void*)this << " SetColorSpace " << pCS->GetFamily() << std::endl;
  if (m_pCS == pCS) {
    std::cerr << (void*)this << " SetColorSpace m_pCS == pCS" << std::endl;
    if (!m_pColorBuffer) {
      std::cerr << (void*)this << " SetColorSpace m_pColorBuffer = pCS->CreateBuf() who knows why" << std::endl;
      m_pColorBuffer = pCS->CreateBuf();
    }

    ReleaseColorSpace();
    m_pCS = pCS;
    return;
  }
  std::cerr << (void*)this << " SetColorSpace m_pCS != pCS" << std::endl;
  ReleaseBuffer();
  ReleaseColorSpace();

  m_pCS = pCS;
  if (pCS) {
    std::cerr << (void*)this << " SetColorSpace m_pColorBuffer = pCS->CreateBuf()" << std::endl;
    m_pColorBuffer = pCS->CreateBuf();
    pCS->GetDefaultColor(m_pColorBuffer->m_Comps);
  }
}

void CPDF_Color::SetValue(const float* comps) {
  std::cerr << (void*)this << " SetValue float* " << std::endl;
  std::cerr << (void*)this << " SetValue float* m_pColorBuffer " << (void*) m_pColorBuffer.get() << std::endl;
  if (!m_pColorBuffer)
    return;
  std::cerr << (void*)this << " SetValue float* IsPatternInternal() " << IsPatternInternal() << std::endl;
  if (!IsPatternInternal()) {
    std::cerr << (void*)this << " SetValue float* memcpy m_pColorBuffer->m_Comps := comps" << std::endl;
    memcpy(m_pColorBuffer->m_Comps, comps, m_pCS->CountComponents() * sizeof(float));
  }
}

void CPDF_Color::SetValue(CPDF_Pattern* pPattern,
                          const float* comps,
                          uint32_t ncomps) {
  std::cerr << (void*)this << " SetValue CPDF_Pattern*" << std::endl;
  if (ncomps > kMaxPatternColorComps)
    return;

  if (!IsPattern()) {
    std::cerr << (void*)this << " SetValue CPDF_Pattern* FX_Free(m_pColorBuffer->m_Comps)" << std::endl;
    FX_Free(m_pColorBuffer->m_Comps);
    m_pCS = CPDF_ColorSpace::GetStockCS(PDFCS_PATTERN);
    std::cerr << (void*)this << " SetValue CPDF_Pattern* m_pColorBuffer = m_pCS->CreateBuf()" << std::endl;
    m_pColorBuffer = m_pCS->CreateBuf();
  }

  CPDF_DocPageData* pDocPageData = nullptr;
  std::cerr << (void*)this << " SetValue CPDF_Pattern*, use m_pColorBuffer as PatternValue" << std::endl;
  PatternValue* pvalue = static_cast<PatternValue*>(m_pColorBuffer.get());
  if (pvalue->m_pPattern) {
    pDocPageData = pvalue->m_pPattern->document()->GetPageData();
    pDocPageData->ReleasePattern(pvalue->m_pPattern->pattern_obj());
  }
  pvalue->m_nComps = ncomps;
  pvalue->m_pPattern = pPattern;
  if (ncomps)
    memcpy(pvalue->m_Comps, comps, ncomps * sizeof(float));

  pvalue->m_pCountedPattern = nullptr;
  if (pPattern) {
    if (!pDocPageData)
      pDocPageData = pPattern->document()->GetPageData();

    pvalue->m_pCountedPattern =
        pDocPageData->FindPatternPtr(pPattern->pattern_obj());
  }
}

void CPDF_Color::Copy(const CPDF_Color* pSrc) {
  ReleaseBuffer();
  ReleaseColorSpace();
  m_pCS = pSrc->m_pCS;
  if (!m_pCS)
    return;

  CPDF_Document* pDoc = m_pCS->GetDocument();
  CPDF_Array* pArray = m_pCS->GetArray();
  if (pDoc && pArray) {
    m_pCS = pDoc->GetPageData()->GetCopiedColorSpace(pArray);
    if (!m_pCS)
      return;
  }
  std::cerr << (void*)this << " Copy m_pColorBuffer = m_pCS->CreateBuf()" << std::endl;
  m_pColorBuffer = m_pCS->CreateBuf();
  std::cerr << (void*)this << " Copy m_pColorBuffer->m_Comps := pSrc->m_pColorBuffer->m_Comps" << std::endl;
  memcpy(m_pColorBuffer->m_Comps, pSrc->m_pColorBuffer->m_Comps, m_pCS->GetBufSize());
  if (!IsPatternInternal())
    return;

  std::cerr << (void*)this << " Copy CPDF_Pattern*, use m_pColorBuffer as PatternValue" << std::endl;
  PatternValue* pValue = static_cast<PatternValue*>(m_pColorBuffer.get());
  CPDF_Pattern* pPattern = pValue->m_pPattern;
  if (!pPattern)
    return;

  pValue->m_pPattern = pPattern->document()->GetPageData()->GetPattern(
      pPattern->pattern_obj(), false, pPattern->parent_matrix());
}

bool CPDF_Color::GetRGB(int* R, int* G, int* B) const {
  std::cerr << (void*)this << " GetRGB m_pColorBuffer " << (void*)m_pColorBuffer.get() << std::endl;
  if (!m_pCS || !m_pColorBuffer)
    return false;

  float r = 0.0f;
  float g = 0.0f;
  float b = 0.0f;
  std::cerr << (void*)this << " GetRGB m_pCS->GetRGB(" << (void*)m_pColorBuffer.get() << ")" << std::endl;
  if (!m_pCS->GetRGB(m_pColorBuffer.get(), &r, &g, &b))
    return false;

  *R = static_cast<int32_t>(r * 255 + 0.5f);
  *G = static_cast<int32_t>(g * 255 + 0.5f);
  *B = static_cast<int32_t>(b * 255 + 0.5f);
  return true;
}

CPDF_Pattern* CPDF_Color::GetPattern() const {
  std::cerr << (void*)this << " GetPattern m_pColorBuffer " << (void*)m_pColorBuffer.get() << std::endl;
  if (!m_pColorBuffer || !IsPatternInternal())
    return nullptr;

  std::cerr << (void*)this << " GetPattern, use m_pColorBuffer as PatternValue" << std::endl;
  const PatternValue* pvalue = static_cast<const PatternValue*>(m_pColorBuffer.get());
  return pvalue->m_pPattern;
}
