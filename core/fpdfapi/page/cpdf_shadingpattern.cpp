// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fpdfapi/page/cpdf_shadingpattern.h"

#include <algorithm>
#include <iostream>

#include "core/fpdfapi/page/cpdf_docpagedata.h"
#include "core/fpdfapi/page/cpdf_function.h"
#include "core/fpdfapi/parser/cpdf_array.h"
#include "core/fpdfapi/parser/cpdf_boolean.h"
#include "core/fpdfapi/parser/cpdf_dictionary.h"
#include "core/fpdfapi/parser/cpdf_document.h"
#include "core/fpdfapi/parser/cpdf_object.h"
#include "core/fpdfapi/parser/cpdf_stream.h"

namespace {

ShadingType ToShadingType(int type) {
  return (type > kInvalidShading && type < kMaxShading)
             ? static_cast<ShadingType>(type)
             : kInvalidShading;
}

}  // namespace

CPDF_ShadingPattern::CPDF_ShadingPattern(CPDF_Document* pDoc,
                                         CPDF_Object* pPatternObj,
                                         bool bShading,
                                         const CFX_Matrix& parentMatrix)
    : CPDF_Pattern(pDoc, bShading ? nullptr : pPatternObj, parentMatrix),
      m_bShadingObj(bShading),
      m_pShadingObj(pPatternObj) {
  assert(document());
  if (!bShading) {
    m_pShadingObj = pattern_obj()->GetDict()->GetDirectObjectFor("Shading");
    SetPatternToFormMatrix();
  }
}

CPDF_ShadingPattern::~CPDF_ShadingPattern() {
  CPDF_ColorSpace* pCountedCS = m_pCountedCS ? m_pCountedCS->get() : nullptr;
  if (pCountedCS) {
    auto* pPageData = document()->GetPageData();
    if (pPageData) {
      m_pCS.Release();  // Give up unowned reference first.
      pPageData->ReleaseColorSpace(pCountedCS->GetArray());
    }
  }
}

CPDF_TilingPattern* CPDF_ShadingPattern::AsTilingPattern() {
  return nullptr;
}

CPDF_ShadingPattern* CPDF_ShadingPattern::AsShadingPattern() {
  return this;
}

bool CPDF_ShadingPattern::Load() {
  if (m_ShadingType != kInvalidShading)
    return true;

  CPDF_Dictionary* pShadingDict =
      m_pShadingObj ? m_pShadingObj->GetDict() : nullptr;
  if (!pShadingDict)
    return false;

  m_pFunctions.clear();
  const CPDF_Object* pFunc = pShadingDict->GetDirectObjectFor("Function");
  if (pFunc) {
    if (const CPDF_Array* pArray = pFunc->AsArray()) {
      m_pFunctions.resize(std::min<size_t>(pArray->GetCount(), 4));
      for (size_t i = 0; i < m_pFunctions.size(); ++i)
        m_pFunctions[i] = CPDF_Function::Load(pArray->GetDirectObjectAt(i));
    } else {
      m_pFunctions.push_back(CPDF_Function::Load(pFunc));
    }
  }
  const CPDF_Object* pCSObj = pShadingDict->GetDirectObjectFor("ColorSpace");
  if (!pCSObj)
    return false;

  CPDF_DocPageData* pDocPageData = document()->GetPageData();
  m_pCS = pDocPageData->GetColorSpace(pCSObj, nullptr);

  // The color space is required and cannot be a Pattern space, according to the
  // PDF 1.7 spec, page 305.
  if (!m_pCS || m_pCS->GetFamily() == PDFCS_PATTERN)
    return false;

  m_pCountedCS = pDocPageData->FindColorSpacePtr(m_pCS->GetArray());
  m_ShadingType = ToShadingType(pShadingDict->GetIntegerFor("ShadingType"));

  static int idx = 0;
  // bool doLog = (m_ShadingType == 3 && idx == 0);
  // std::cerr << " CPDF_ShadingPattern::Load loaded m_ShadingType=" << m_ShadingType << ", idx=" << idx << std::endl;
  ++idx;

  if (m_ShadingType == 3) {
    const CPDF_Array* pCoords = pShadingDict->GetArrayFor("Coords");
    if (pCoords) {
      float start_x = pCoords->GetNumberAt(0);
      float start_y = pCoords->GetNumberAt(1);
      if (idx == 1) {
        std::cerr << "CPDF_ShadingPattern(" << (void*)this << ")::Load LOADED pShadingDict " << (void*)pShadingDict << " idx " << idx << " start_x " << start_x << " start_y " << start_y << std::endl;
      } else {
        std::cerr << "CPDF_ShadingPattern(" << (void*)this << ")::Load SKIPPED pShadingDict " << (void*)pShadingDict << " idx " << idx << " start_x " << start_x << " start_y " << start_y << std::endl;
        // return false;
      }
    } else {
      std::cerr << "CPDF_ShadingPattern::Load SKIPPED !pCoords" << std::endl;
      // return false;
    }
  }

  // if (doLog) {
  //   std::cerr << "CPDF_ShadingPattern::Load loaded m_ShadingType=" << m_ShadingType << std::endl;
  //   pShadingDict->SetNewFor<CPDF_Boolean>("doLog", true);
  //   // return false;
  // }

  return Validate(false);
}

bool CPDF_ShadingPattern::Validate(bool doLog) const {
  if (m_ShadingType == kInvalidShading)
    return false;

  // We expect to have a stream if our shading type is a mesh.
  if (IsMeshShading() && !ToStream(m_pShadingObj.Get()))
    return false;

  // Validate color space
  switch (m_ShadingType) {
    case kFunctionBasedShading:
    case kAxialShading:
    case kRadialShading: {
      if (m_pCS->GetFamily() == PDFCS_INDEXED)
        return false;
      break;
    }
    case kFreeFormGouraudTriangleMeshShading:
    case kLatticeFormGouraudTriangleMeshShading:
    case kCoonsPatchMeshShading:
    case kTensorProductPatchMeshShading: {
      if (!m_pFunctions.empty() && m_pCS->GetFamily() == PDFCS_INDEXED)
        return false;
      break;
    }
    default: {
      NOTREACHED();
      return false;
    }
  }

  uint32_t nNumColorSpaceComponents = m_pCS->CountComponents();
  switch (m_ShadingType) {
    case kFunctionBasedShading: {
      // Either one 2-to-N function or N 2-to-1 functions.
      return ValidateFunctions(1, 2, nNumColorSpaceComponents) ||
             ValidateFunctions(nNumColorSpaceComponents, 2, 1);
    }
    case kAxialShading:
    case kRadialShading: {
      // Either one 1-to-N function or N 1-to-1 functions.
      return ValidateFunctions(1, 1, nNumColorSpaceComponents) ||
             ValidateFunctions(nNumColorSpaceComponents, 1, 1);
    }
    case kFreeFormGouraudTriangleMeshShading:
    case kLatticeFormGouraudTriangleMeshShading:
    case kCoonsPatchMeshShading:
    case kTensorProductPatchMeshShading: {
      // Either no function, one 1-to-N function, or N 1-to-1 functions.
      return m_pFunctions.empty() ||
             ValidateFunctions(1, 1, nNumColorSpaceComponents) ||
             ValidateFunctions(nNumColorSpaceComponents, 1, 1);
    }
    default:
      break;
  }
  NOTREACHED();
  return false;
}

bool CPDF_ShadingPattern::ValidateFunctions(
    uint32_t nExpectedNumFunctions,
    uint32_t nExpectedNumInputs,
    uint32_t nExpectedNumOutputs) const {
  if (m_pFunctions.size() != nExpectedNumFunctions)
    return false;

  pdfium::base::CheckedNumeric<uint32_t> nTotalOutputs = 0;
  for (const auto& function : m_pFunctions) {
    if (!function)
      return false;

    if (function->CountInputs() != nExpectedNumInputs ||
        function->CountOutputs() != nExpectedNumOutputs) {
      return false;
    }

    nTotalOutputs += function->CountOutputs();
  }

  return nTotalOutputs.IsValid();
}
