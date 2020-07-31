// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fpdfapi/page/cpdf_allstates.h"

#include <algorithm>
#include <utility>
#include <vector>

#include "core/fpdfapi/font/cpdf_font.h"
#include "core/fpdfapi/page/cpdf_pageobjectholder.h"
#include "core/fpdfapi/page/cpdf_streamcontentparser.h"
#include "core/fpdfapi/parser/cpdf_array.h"
#include "core/fpdfapi/parser/cpdf_dictionary.h"
#include "core/fpdfapi/parser/fpdf_parser_utility.h"
#include "core/fxge/cfx_graphstatedata.h"
#include "third_party/base/compiler_specific.h"
#include "third_party/base/stl_util.h"

CPDF_AllStates::CPDF_AllStates() = default;

CPDF_AllStates::~CPDF_AllStates() = default;

void CPDF_AllStates::Copy(const CPDF_AllStates& src) {
  CopyStates(src);
  m_TextMatrix = src.m_TextMatrix;
  m_ParentMatrix = src.m_ParentMatrix;
  m_CTM = src.m_CTM;
  m_TextPos = src.m_TextPos;
  m_TextLinePos = src.m_TextLinePos;
  m_TextLeading = src.m_TextLeading;
  m_TextRise = src.m_TextRise;
  m_TextHorzScale = src.m_TextHorzScale;
}

void CPDF_AllStates::SetLineDash(const CPDF_Array* pArray,
                                 float phase,
                                 float scale) {
  std::vector<float> dashes = ReadArrayElementsToVector(pArray, pArray->size());
  m_GraphState.SetLineDash(std::move(dashes), phase, scale);
}

void CPDF_AllStates::ProcessExtGS(CPDF_Dictionary* pGS,
                                  CPDF_StreamContentParser* pParser) {
  CPDF_DictionaryLocker locker(pGS);
  for (const auto& it : locker) {
    const ByteString& key_str = it.first;
    CPDF_Object* pElement = it.second.Get();
    CPDF_Object* pObject = pElement ? pElement->GetDirect() : nullptr;
    if (!pObject)
      continue;

    uint32_t key = key_str.GetID();
    switch (key) {
      case FX_GetByteStringID("LW"):
        m_GraphState.SetLineWidth(pObject->GetNumber());
        break;
      case FX_GetByteStringID("LC"):
        m_GraphState.SetLineCap(
            static_cast<CFX_GraphStateData::LineCap>(pObject->GetInteger()));
        break;
      case FX_GetByteStringID("LJ"):
        m_GraphState.SetLineJoin(
            static_cast<CFX_GraphStateData::LineJoin>(pObject->GetInteger()));
        break;
      case FX_GetByteStringID("ML"):
        m_GraphState.SetMiterLimit(pObject->GetNumber());
        break;
      case FX_GetByteStringID("D"): {
        CPDF_Array* pDash = pObject->AsArray();
        if (!pDash)
          break;

        CPDF_Array* pArray = pDash->GetArrayAt(0);
        if (!pArray)
          break;

        SetLineDash(pArray, pDash->GetNumberAt(1), 1.0f);
        break;
      }
      case FX_GetByteStringID("RI"):
        m_GeneralState.SetRenderIntent(pObject->GetString());
        break;
      case FX_GetByteStringID("Font"): {
        CPDF_Array* pFont = pObject->AsArray();
        if (!pFont)
          break;

        m_TextState.SetFontSize(pFont->GetNumberAt(1));
        m_TextState.SetFont(pParser->FindFont(pFont->GetStringAt(0)));
        break;
      }
      case FX_GetByteStringID("TR"):
        if (pGS->KeyExist("TR2")) {
          continue;
        }
        FALLTHROUGH;
      case FX_GetByteStringID("TR2"):
        m_GeneralState.SetTR(pObject && !pObject->IsName() ? pObject : nullptr);
        break;
      case FX_GetByteStringID("BM"): {
        CPDF_Array* pArray = pObject->AsArray();
        m_GeneralState.SetBlendMode(pArray ? pArray->GetStringAt(0)
                                           : pObject->GetString());
        if (m_GeneralState.GetBlendType() > BlendMode::kMultiply)
          pParser->GetPageObjectHolder()->SetBackgroundAlphaNeeded(true);
        break;
      }
      case FX_GetByteStringID("SMas"):
        if (ToDictionary(pObject)) {
          m_GeneralState.SetSoftMask(pObject);
          m_GeneralState.SetSMaskMatrix(pParser->GetCurStates()->m_CTM);
        } else {
          m_GeneralState.SetSoftMask(nullptr);
        }
        break;
      case FX_GetByteStringID("CA"):
        m_GeneralState.SetStrokeAlpha(
            pdfium::clamp(pObject->GetNumber(), 0.0f, 1.0f));
        break;
      case FX_GetByteStringID("ca"):
        m_GeneralState.SetFillAlpha(
            pdfium::clamp(pObject->GetNumber(), 0.0f, 1.0f));
        break;
      case FX_GetByteStringID("OP"):
        m_GeneralState.SetStrokeOP(!!pObject->GetInteger());
        if (!pGS->KeyExist("op"))
          m_GeneralState.SetFillOP(!!pObject->GetInteger());
        break;
      case FX_GetByteStringID("op"):
        m_GeneralState.SetFillOP(!!pObject->GetInteger());
        break;
      case FX_GetByteStringID("OPM"):
        m_GeneralState.SetOPMode(pObject->GetInteger());
        break;
      case FX_GetByteStringID("BG"):
        if (pGS->KeyExist("BG2")) {
          continue;
        }
        FALLTHROUGH;
      case FX_GetByteStringID("BG2"):
        m_GeneralState.SetBG(pObject);
        break;
      case FX_GetByteStringID("UCR"):
        if (pGS->KeyExist("UCR2")) {
          continue;
        }
        FALLTHROUGH;
      case FX_GetByteStringID("UCR2"):
        m_GeneralState.SetUCR(pObject);
        break;
      case FX_GetByteStringID("HT"):
        m_GeneralState.SetHT(pObject);
        break;
      case FX_GetByteStringID("FL"):
        m_GeneralState.SetFlatness(pObject->GetNumber());
        break;
      case FX_GetByteStringID("SM"):
        m_GeneralState.SetSmoothness(pObject->GetNumber());
        break;
      case FX_GetByteStringID("SA"):
        m_GeneralState.SetStrokeAdjust(!!pObject->GetInteger());
        break;
      case FX_GetByteStringID("AIS"):
        m_GeneralState.SetAlphaSource(!!pObject->GetInteger());
        break;
      case FX_GetByteStringID("TK"):
        m_GeneralState.SetTextKnockout(!!pObject->GetInteger());
        break;
    }
  }
  m_GeneralState.SetMatrix(m_CTM);
}
