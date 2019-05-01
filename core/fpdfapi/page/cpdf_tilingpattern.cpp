// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fpdfapi/page/cpdf_tilingpattern.h"

#include "core/fpdfapi/page/cpdf_allstates.h"
#include "core/fpdfapi/page/cpdf_form.h"
#include "core/fpdfapi/page/cpdf_pageobject.h"
#include "core/fpdfapi/parser/cpdf_dictionary.h"
#include "core/fpdfapi/parser/cpdf_object.h"
#include "core/fpdfapi/parser/cpdf_stream.h"
#include "third_party/base/ptr_util.h"

CPDF_TilingPattern::CPDF_TilingPattern(CPDF_Document* pDoc,
                                       CPDF_Object* pPatternObj,
                                       const CFX_Matrix& parentMatrix)
    : CPDF_Pattern(pDoc, pPatternObj, parentMatrix) {
  ASSERT(document());
  m_bColored = pattern_obj()->GetDict()->GetIntegerFor("PaintType") == 1;
  SetPatternToFormMatrix();
}

CPDF_TilingPattern::~CPDF_TilingPattern() {}

CPDF_TilingPattern* CPDF_TilingPattern::AsTilingPattern() {
  return this;
}

CPDF_ShadingPattern* CPDF_TilingPattern::AsShadingPattern() {
  return nullptr;
}

std::unique_ptr<CPDF_Form> CPDF_TilingPattern::Load(CPDF_PageObject* pPageObj) {
  const CPDF_Dictionary* pDict = pattern_obj()->GetDict();
  if (!pDict)
    return nullptr;

  m_bColored = pDict->GetIntegerFor("PaintType") == 1;
  m_XStep = static_cast<float>(fabs(pDict->GetNumberFor("XStep")));
  m_YStep = static_cast<float>(fabs(pDict->GetNumberFor("YStep")));

  CPDF_Stream* pStream = pattern_obj()->AsStream();
  if (!pStream)
    return nullptr;

  const CFX_Matrix& matrix = parent_matrix();
  std::unique_ptr<CPDF_Form> form =
      pdfium::MakeUnique<CPDF_Form>(document(), nullptr, pStream);

  CPDF_AllStates allStates;
  allStates.CopyStates(*pPageObj);
  // Reset color state to default. The current pattern is set in the color
  // state and this would lead to recursion problems. We also reset the
  // clip path as it isn't relevant for pattern rendering either.
  allStates.m_ColorState.SetDefault();
  allStates.m_ClipPath.SetNull();
  form->ParseContent(&allStates, &matrix, nullptr, nullptr);
  m_BBox = pDict->GetRectFor("BBox");
  return form;
}
