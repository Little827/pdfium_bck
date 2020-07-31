// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fpdfapi/page/cpdf_streamcontentparser.h"

#include <algorithm>
#include <memory>
#include <utility>
#include <vector>

#include "core/fpdfapi/font/cpdf_font.h"
#include "core/fpdfapi/font/cpdf_type3font.h"
#include "core/fpdfapi/page/cpdf_allstates.h"
#include "core/fpdfapi/page/cpdf_docpagedata.h"
#include "core/fpdfapi/page/cpdf_form.h"
#include "core/fpdfapi/page/cpdf_formobject.h"
#include "core/fpdfapi/page/cpdf_image.h"
#include "core/fpdfapi/page/cpdf_imageobject.h"
#include "core/fpdfapi/page/cpdf_meshstream.h"
#include "core/fpdfapi/page/cpdf_pageobject.h"
#include "core/fpdfapi/page/cpdf_pathobject.h"
#include "core/fpdfapi/page/cpdf_shadingobject.h"
#include "core/fpdfapi/page/cpdf_shadingpattern.h"
#include "core/fpdfapi/page/cpdf_streamparser.h"
#include "core/fpdfapi/page/cpdf_textobject.h"
#include "core/fpdfapi/parser/cpdf_array.h"
#include "core/fpdfapi/parser/cpdf_dictionary.h"
#include "core/fpdfapi/parser/cpdf_document.h"
#include "core/fpdfapi/parser/cpdf_name.h"
#include "core/fpdfapi/parser/cpdf_number.h"
#include "core/fpdfapi/parser/cpdf_reference.h"
#include "core/fpdfapi/parser/cpdf_stream.h"
#include "core/fpdfapi/parser/fpdf_parser_utility.h"
#include "core/fxcrt/fx_safe_types.h"
#include "core/fxge/cfx_graphstatedata.h"
#include "third_party/base/logging.h"
#include "third_party/base/span.h"
#include "third_party/base/stl_util.h"

namespace {

const int kMaxFormLevel = 30;

const int kSingleCoordinatePair = 1;
const int kTensorCoordinatePairs = 16;
const int kCoonsCoordinatePairs = 12;
const int kSingleColorPerPatch = 1;
const int kQuadColorsPerPatch = 4;

const char kPathOperatorSubpath = 'm';
const char kPathOperatorLine = 'l';
const char kPathOperatorCubicBezier1 = 'c';
const char kPathOperatorCubicBezier2 = 'v';
const char kPathOperatorCubicBezier3 = 'y';
const char kPathOperatorClosePath = 'h';
const char kPathOperatorRectangle[] = "re";

class CPDF_StreamParserAutoClearer {
 public:
  CPDF_StreamParserAutoClearer(UnownedPtr<CPDF_StreamParser>* scoped_variable,
                               CPDF_StreamParser* new_parser)
      : scoped_variable_(scoped_variable) {
    *scoped_variable_ = new_parser;
  }
  ~CPDF_StreamParserAutoClearer() { *scoped_variable_ = nullptr; }

 private:
  UnownedPtr<CPDF_StreamParser>* scoped_variable_;
};

CFX_FloatRect GetShadingBBox(CPDF_ShadingPattern* pShading,
                             const CFX_Matrix& matrix) {
  ShadingType type = pShading->GetShadingType();
  const CPDF_Stream* pStream = ToStream(pShading->GetShadingObject());
  RetainPtr<CPDF_ColorSpace> pCS = pShading->GetCS();
  if (!pStream || !pCS)
    return CFX_FloatRect();

  CPDF_MeshStream stream(type, pShading->GetFuncs(), pStream, pCS);
  if (!stream.Load())
    return CFX_FloatRect();

  CFX_FloatRect rect;
  bool bStarted = false;
  bool bGouraud = type == kFreeFormGouraudTriangleMeshShading ||
                  type == kLatticeFormGouraudTriangleMeshShading;

  int point_count = kSingleCoordinatePair;
  if (type == kTensorProductPatchMeshShading)
    point_count = kTensorCoordinatePairs;
  else if (type == kCoonsPatchMeshShading)
    point_count = kCoonsCoordinatePairs;

  int color_count = kSingleColorPerPatch;
  if (type == kCoonsPatchMeshShading || type == kTensorProductPatchMeshShading)
    color_count = kQuadColorsPerPatch;

  while (!stream.BitStream()->IsEOF()) {
    uint32_t flag = 0;
    if (type != kLatticeFormGouraudTriangleMeshShading) {
      if (!stream.CanReadFlag())
        break;
      flag = stream.ReadFlag();
    }

    if (!bGouraud && flag) {
      point_count -= 4;
      color_count -= 2;
    }

    for (int i = 0; i < point_count; i++) {
      if (!stream.CanReadCoords())
        break;
      CFX_PointF origin = stream.ReadCoords();
      if (bStarted) {
        rect.UpdateRect(origin);
      } else {
        rect.InitRect(origin);
        bStarted = true;
      }
    }
    FX_SAFE_UINT32 nBits = stream.Components();
    nBits *= stream.ComponentBits();
    nBits *= color_count;
    if (!nBits.IsValid())
      break;

    stream.BitStream()->SkipBits(nBits.ValueOrDie());
    if (bGouraud)
      stream.BitStream()->ByteAlign();
  }
  return matrix.TransformRect(rect);
}

struct AbbrPair {
  const char* abbr;
  const char* full_name;
};

const AbbrPair kInlineKeyAbbr[] = {
    {"BPC", "BitsPerComponent"}, {"CS", "ColorSpace"}, {"D", "Decode"},
    {"DP", "DecodeParms"},       {"F", "Filter"},      {"H", "Height"},
    {"IM", "ImageMask"},         {"I", "Interpolate"}, {"W", "Width"},
};

const AbbrPair kInlineValueAbbr[] = {
    {"G", "DeviceGray"},       {"RGB", "DeviceRGB"},
    {"CMYK", "DeviceCMYK"},    {"I", "Indexed"},
    {"AHx", "ASCIIHexDecode"}, {"A85", "ASCII85Decode"},
    {"LZW", "LZWDecode"},      {"Fl", "FlateDecode"},
    {"RL", "RunLengthDecode"}, {"CCF", "CCITTFaxDecode"},
    {"DCT", "DCTDecode"},
};

struct AbbrReplacementOp {
  bool is_replace_key;
  ByteString key;
  ByteStringView replacement;
};

ByteStringView FindFullName(const AbbrPair* table,
                            size_t count,
                            ByteStringView abbr) {
  auto* it = std::find_if(table, table + count, [abbr](const AbbrPair& pair) {
    return pair.abbr == abbr;
  });
  return it != table + count ? ByteStringView(it->full_name) : ByteStringView();
}

void ReplaceAbbr(CPDF_Object* pObj);

void ReplaceAbbrInDictionary(CPDF_Dictionary* pDict) {
  std::vector<AbbrReplacementOp> replacements;
  {
    CPDF_DictionaryLocker locker(pDict);
    for (const auto& it : locker) {
      ByteString key = it.first;
      CPDF_Object* value = it.second.Get();
      ByteStringView fullname = FindFullName(
          kInlineKeyAbbr, pdfium::size(kInlineKeyAbbr), key.AsStringView());
      if (!fullname.IsEmpty()) {
        AbbrReplacementOp op;
        op.is_replace_key = true;
        op.key = std::move(key);
        op.replacement = fullname;
        replacements.push_back(op);
        key = fullname;
      }

      if (value->IsName()) {
        ByteString name = value->GetString();
        fullname =
            FindFullName(kInlineValueAbbr, pdfium::size(kInlineValueAbbr),
                         name.AsStringView());
        if (!fullname.IsEmpty()) {
          AbbrReplacementOp op;
          op.is_replace_key = false;
          op.key = key;
          op.replacement = fullname;
          replacements.push_back(op);
        }
      } else {
        ReplaceAbbr(value);
      }
    }
  }
  for (const auto& op : replacements) {
    if (op.is_replace_key)
      pDict->ReplaceKey(op.key, ByteString(op.replacement));
    else
      pDict->SetNewFor<CPDF_Name>(op.key, ByteString(op.replacement));
  }
}

void ReplaceAbbrInArray(CPDF_Array* pArray) {
  for (size_t i = 0; i < pArray->size(); ++i) {
    CPDF_Object* pElement = pArray->GetObjectAt(i);
    if (pElement->IsName()) {
      ByteString name = pElement->GetString();
      ByteStringView fullname =
          FindFullName(kInlineValueAbbr, pdfium::size(kInlineValueAbbr),
                       name.AsStringView());
      if (!fullname.IsEmpty())
        pArray->SetNewAt<CPDF_Name>(i, ByteString(fullname));
    } else {
      ReplaceAbbr(pElement);
    }
  }
}

void ReplaceAbbr(CPDF_Object* pObj) {
  CPDF_Dictionary* pDict = pObj->AsDictionary();
  if (pDict) {
    ReplaceAbbrInDictionary(pDict);
    return;
  }

  CPDF_Array* pArray = pObj->AsArray();
  if (pArray)
    ReplaceAbbrInArray(pArray);
}

}  // namespace

CPDF_StreamContentParser::CPDF_StreamContentParser(
    CPDF_Document* pDocument,
    CPDF_Dictionary* pPageResources,
    CPDF_Dictionary* pParentResources,
    const CFX_Matrix* pmtContentToUser,
    CPDF_PageObjectHolder* pObjHolder,
    CPDF_Dictionary* pResources,
    const CFX_FloatRect& rcBBox,
    const CPDF_AllStates* pStates,
    std::set<const uint8_t*>* pParsedSet)
    : m_pDocument(pDocument),
      m_pPageResources(pPageResources),
      m_pParentResources(pParentResources),
      m_pResources(CPDF_Form::ChooseResourcesDict(pResources,
                                                  pParentResources,
                                                  pPageResources)),
      m_pObjectHolder(pObjHolder),
      m_ParsedSet(pParsedSet),
      m_BBox(rcBBox),
      m_pCurStates(std::make_unique<CPDF_AllStates>()) {
  if (pmtContentToUser)
    m_mtContentToUser = *pmtContentToUser;
  if (pStates) {
    m_pCurStates->Copy(*pStates);
  } else {
    m_pCurStates->m_GeneralState.Emplace();
    m_pCurStates->m_GraphState.Emplace();
    m_pCurStates->m_TextState.Emplace();
    m_pCurStates->m_ColorState.Emplace();
  }

  // Add the sentinel.
  m_ContentMarksStack.push(std::make_unique<CPDF_ContentMarks>());
}

CPDF_StreamContentParser::~CPDF_StreamContentParser() {
  ClearAllParams();
}

int CPDF_StreamContentParser::GetNextParamPos() {
  if (m_ParamCount == kParamBufSize) {
    m_ParamStartPos++;
    if (m_ParamStartPos == kParamBufSize) {
      m_ParamStartPos = 0;
    }
    if (m_ParamBuf[m_ParamStartPos].m_Type == ContentParam::OBJECT)
      m_ParamBuf[m_ParamStartPos].m_pObject.Reset();

    return m_ParamStartPos;
  }
  int index = m_ParamStartPos + m_ParamCount;
  if (index >= kParamBufSize) {
    index -= kParamBufSize;
  }
  m_ParamCount++;
  return index;
}

void CPDF_StreamContentParser::AddNameParam(ByteStringView bsName) {
  ContentParam& param = m_ParamBuf[GetNextParamPos()];
  param.m_Type = ContentParam::NAME;
  param.m_Name =
      bsName.Contains('#') ? PDF_NameDecode(bsName) : ByteString(bsName);
}

void CPDF_StreamContentParser::AddNumberParam(ByteStringView str) {
  ContentParam& param = m_ParamBuf[GetNextParamPos()];
  param.m_Type = ContentParam::NUMBER;
  param.m_Number = FX_Number(str);
}

void CPDF_StreamContentParser::AddObjectParam(RetainPtr<CPDF_Object> pObj) {
  ContentParam& param = m_ParamBuf[GetNextParamPos()];
  param.m_Type = ContentParam::OBJECT;
  param.m_pObject = std::move(pObj);
}

void CPDF_StreamContentParser::ClearAllParams() {
  uint32_t index = m_ParamStartPos;
  for (uint32_t i = 0; i < m_ParamCount; i++) {
    if (m_ParamBuf[index].m_Type == ContentParam::OBJECT)
      m_ParamBuf[index].m_pObject.Reset();
    index++;
    if (index == kParamBufSize)
      index = 0;
  }
  m_ParamStartPos = 0;
  m_ParamCount = 0;
}

CPDF_Object* CPDF_StreamContentParser::GetObject(uint32_t index) {
  if (index >= m_ParamCount) {
    return nullptr;
  }
  int real_index = m_ParamStartPos + m_ParamCount - index - 1;
  if (real_index >= kParamBufSize) {
    real_index -= kParamBufSize;
  }
  ContentParam& param = m_ParamBuf[real_index];
  if (param.m_Type == ContentParam::NUMBER) {
    param.m_Type = ContentParam::OBJECT;
    param.m_pObject =
        param.m_Number.IsInteger()
            ? pdfium::MakeRetain<CPDF_Number>(param.m_Number.GetSigned())
            : pdfium::MakeRetain<CPDF_Number>(param.m_Number.GetFloat());
    return param.m_pObject.Get();
  }
  if (param.m_Type == ContentParam::NAME) {
    param.m_Type = ContentParam::OBJECT;
    param.m_pObject = m_pDocument->New<CPDF_Name>(param.m_Name);
    return param.m_pObject.Get();
  }
  if (param.m_Type == ContentParam::OBJECT)
    return param.m_pObject.Get();

  NOTREACHED();
  return nullptr;
}

ByteString CPDF_StreamContentParser::GetString(uint32_t index) const {
  if (index >= m_ParamCount)
    return ByteString();

  int real_index = m_ParamStartPos + m_ParamCount - index - 1;
  if (real_index >= kParamBufSize)
    real_index -= kParamBufSize;

  const ContentParam& param = m_ParamBuf[real_index];
  if (param.m_Type == ContentParam::NAME)
    return param.m_Name;

  if (param.m_Type == 0 && param.m_pObject)
    return param.m_pObject->GetString();

  return ByteString();
}

float CPDF_StreamContentParser::GetNumber(uint32_t index) const {
  if (index >= m_ParamCount)
    return 0;

  int real_index = m_ParamStartPos + m_ParamCount - index - 1;
  if (real_index >= kParamBufSize)
    real_index -= kParamBufSize;

  const ContentParam& param = m_ParamBuf[real_index];
  if (param.m_Type == ContentParam::NUMBER)
    return param.m_Number.GetFloat();

  if (param.m_Type == 0 && param.m_pObject)
    return param.m_pObject->GetNumber();

  return 0;
}

std::vector<float> CPDF_StreamContentParser::GetNumbers(size_t count) const {
  std::vector<float> values(count);
  for (size_t i = 0; i < count; ++i)
    values[i] = GetNumber(count - i - 1);
  return values;
}

void CPDF_StreamContentParser::SetGraphicStates(CPDF_PageObject* pObj,
                                                bool bColor,
                                                bool bText,
                                                bool bGraph) {
  pObj->m_GeneralState = m_pCurStates->m_GeneralState;
  pObj->m_ClipPath = m_pCurStates->m_ClipPath;
  pObj->m_ContentMarks = *m_ContentMarksStack.top();
  if (bColor) {
    pObj->m_ColorState = m_pCurStates->m_ColorState;
  }
  if (bGraph) {
    pObj->m_GraphState = m_pCurStates->m_GraphState;
  }
  if (bText) {
    pObj->m_TextState = m_pCurStates->m_TextState;
  }
}

// static
CPDF_StreamContentParser::OpCodes
CPDF_StreamContentParser::InitializeOpCodes() {
  return OpCodes({
      {FX_GetByteStringID("\""),
       &CPDF_StreamContentParser::Handle_NextLineShowText_Space},
      {FX_GetByteStringID("'"),
       &CPDF_StreamContentParser::Handle_NextLineShowText},
      {FX_GetByteStringID("B"),
       &CPDF_StreamContentParser::Handle_FillStrokePath},
      {FX_GetByteStringID("B*"),
       &CPDF_StreamContentParser::Handle_EOFillStrokePath},
      {FX_GetByteStringID("BDC"),
       &CPDF_StreamContentParser::Handle_BeginMarkedContent_Dictionary},
      {FX_GetByteStringID("BI"), &CPDF_StreamContentParser::Handle_BeginImage},
      {FX_GetByteStringID("BMC"),
       &CPDF_StreamContentParser::Handle_BeginMarkedContent},
      {FX_GetByteStringID("BT"), &CPDF_StreamContentParser::Handle_BeginText},
      {FX_GetByteStringID("CS"),
       &CPDF_StreamContentParser::Handle_SetColorSpace_Stroke},
      {FX_GetByteStringID("DP"),
       &CPDF_StreamContentParser::Handle_MarkPlace_Dictionary},
      {FX_GetByteStringID("Do"),
       &CPDF_StreamContentParser::Handle_ExecuteXObject},
      {FX_GetByteStringID("EI"), &CPDF_StreamContentParser::Handle_EndImage},
      {FX_GetByteStringID("EMC"),
       &CPDF_StreamContentParser::Handle_EndMarkedContent},
      {FX_GetByteStringID("ET"), &CPDF_StreamContentParser::Handle_EndText},
      {FX_GetByteStringID("F"), &CPDF_StreamContentParser::Handle_FillPathOld},
      {FX_GetByteStringID("G"),
       &CPDF_StreamContentParser::Handle_SetGray_Stroke},
      {FX_GetByteStringID("ID"),
       &CPDF_StreamContentParser::Handle_BeginImageData},
      {FX_GetByteStringID("J"), &CPDF_StreamContentParser::Handle_SetLineCap},
      {FX_GetByteStringID("K"),
       &CPDF_StreamContentParser::Handle_SetCMYKColor_Stroke},
      {FX_GetByteStringID("M"),
       &CPDF_StreamContentParser::Handle_SetMiterLimit},
      {FX_GetByteStringID("MP"), &CPDF_StreamContentParser::Handle_MarkPlace},
      {FX_GetByteStringID("Q"),
       &CPDF_StreamContentParser::Handle_RestoreGraphState},
      {FX_GetByteStringID("RG"),
       &CPDF_StreamContentParser::Handle_SetRGBColor_Stroke},
      {FX_GetByteStringID("S"), &CPDF_StreamContentParser::Handle_StrokePath},
      {FX_GetByteStringID("SC"),
       &CPDF_StreamContentParser::Handle_SetColor_Stroke},
      {FX_GetByteStringID("SCN"),
       &CPDF_StreamContentParser::Handle_SetColorPS_Stroke},
      {FX_GetByteStringID("T*"),
       &CPDF_StreamContentParser::Handle_MoveToNextLine},
      {FX_GetByteStringID("TD"),
       &CPDF_StreamContentParser::Handle_MoveTextPoint_SetLeading},
      {FX_GetByteStringID("TJ"),
       &CPDF_StreamContentParser::Handle_ShowText_Positioning},
      {FX_GetByteStringID("TL"),
       &CPDF_StreamContentParser::Handle_SetTextLeading},
      {FX_GetByteStringID("Tc"),
       &CPDF_StreamContentParser::Handle_SetCharSpace},
      {FX_GetByteStringID("Td"),
       &CPDF_StreamContentParser::Handle_MoveTextPoint},
      {FX_GetByteStringID("Tf"), &CPDF_StreamContentParser::Handle_SetFont},
      {FX_GetByteStringID("Tj"), &CPDF_StreamContentParser::Handle_ShowText},
      {FX_GetByteStringID("Tm"),
       &CPDF_StreamContentParser::Handle_SetTextMatrix},
      {FX_GetByteStringID("Tr"),
       &CPDF_StreamContentParser::Handle_SetTextRenderMode},
      {FX_GetByteStringID("Ts"), &CPDF_StreamContentParser::Handle_SetTextRise},
      {FX_GetByteStringID("Tw"),
       &CPDF_StreamContentParser::Handle_SetWordSpace},
      {FX_GetByteStringID("Tz"),
       &CPDF_StreamContentParser::Handle_SetHorzScale},
      {FX_GetByteStringID("W"), &CPDF_StreamContentParser::Handle_Clip},
      {FX_GetByteStringID("W*"), &CPDF_StreamContentParser::Handle_EOClip},
      {FX_GetByteStringID("b"),
       &CPDF_StreamContentParser::Handle_CloseFillStrokePath},
      {FX_GetByteStringID("b*"),
       &CPDF_StreamContentParser::Handle_CloseEOFillStrokePath},
      {FX_GetByteStringID("c"), &CPDF_StreamContentParser::Handle_CurveTo_123},
      {FX_GetByteStringID("cm"),
       &CPDF_StreamContentParser::Handle_ConcatMatrix},
      {FX_GetByteStringID("cs"),
       &CPDF_StreamContentParser::Handle_SetColorSpace_Fill},
      {FX_GetByteStringID("d"), &CPDF_StreamContentParser::Handle_SetDash},
      {FX_GetByteStringID("d0"),
       &CPDF_StreamContentParser::Handle_SetCharWidth},
      {FX_GetByteStringID("d1"),
       &CPDF_StreamContentParser::Handle_SetCachedDevice},
      {FX_GetByteStringID("f"), &CPDF_StreamContentParser::Handle_FillPath},
      {FX_GetByteStringID("f*"), &CPDF_StreamContentParser::Handle_EOFillPath},
      {FX_GetByteStringID("g"), &CPDF_StreamContentParser::Handle_SetGray_Fill},
      {FX_GetByteStringID("gs"),
       &CPDF_StreamContentParser::Handle_SetExtendGraphState},
      {FX_GetByteStringID("h"), &CPDF_StreamContentParser::Handle_ClosePath},
      {FX_GetByteStringID("i"), &CPDF_StreamContentParser::Handle_SetFlat},
      {FX_GetByteStringID("j"), &CPDF_StreamContentParser::Handle_SetLineJoin},
      {FX_GetByteStringID("k"),
       &CPDF_StreamContentParser::Handle_SetCMYKColor_Fill},
      {FX_GetByteStringID("l"), &CPDF_StreamContentParser::Handle_LineTo},
      {FX_GetByteStringID("m"), &CPDF_StreamContentParser::Handle_MoveTo},
      {FX_GetByteStringID("n"), &CPDF_StreamContentParser::Handle_EndPath},
      {FX_GetByteStringID("q"),
       &CPDF_StreamContentParser::Handle_SaveGraphState},
      {FX_GetByteStringID("re"), &CPDF_StreamContentParser::Handle_Rectangle},
      {FX_GetByteStringID("rg"),
       &CPDF_StreamContentParser::Handle_SetRGBColor_Fill},
      {FX_GetByteStringID("ri"),
       &CPDF_StreamContentParser::Handle_SetRenderIntent},
      {FX_GetByteStringID("s"),
       &CPDF_StreamContentParser::Handle_CloseStrokePath},
      {FX_GetByteStringID("sc"),
       &CPDF_StreamContentParser::Handle_SetColor_Fill},
      {FX_GetByteStringID("scn"),
       &CPDF_StreamContentParser::Handle_SetColorPS_Fill},
      {FX_GetByteStringID("sh"), &CPDF_StreamContentParser::Handle_ShadeFill},
      {FX_GetByteStringID("v"), &CPDF_StreamContentParser::Handle_CurveTo_23},
      {FX_GetByteStringID("w"), &CPDF_StreamContentParser::Handle_SetLineWidth},
      {FX_GetByteStringID("y"), &CPDF_StreamContentParser::Handle_CurveTo_13},
  });
}

void CPDF_StreamContentParser::OnOperator(ByteStringView op) {
  static const OpCodes s_OpCodes = InitializeOpCodes();

  auto it = s_OpCodes.find(op.GetID());
  if (it != s_OpCodes.end())
    (this->*it->second)();
}

void CPDF_StreamContentParser::Handle_CloseFillStrokePath() {
  Handle_ClosePath();
  AddPathObject(CFX_FillRenderOptions::FillType::kWinding, true);
}

void CPDF_StreamContentParser::Handle_FillStrokePath() {
  AddPathObject(CFX_FillRenderOptions::FillType::kWinding, true);
}

void CPDF_StreamContentParser::Handle_CloseEOFillStrokePath() {
  AddPathPoint(m_PathStartX, m_PathStartY, FXPT_TYPE::LineTo, true);
  AddPathObject(CFX_FillRenderOptions::FillType::kEvenOdd, true);
}

void CPDF_StreamContentParser::Handle_EOFillStrokePath() {
  AddPathObject(CFX_FillRenderOptions::FillType::kEvenOdd, true);
}

void CPDF_StreamContentParser::Handle_BeginMarkedContent_Dictionary() {
  CPDF_Object* pProperty = GetObject(0);
  if (!pProperty)
    return;

  ByteString tag = GetString(1);
  std::unique_ptr<CPDF_ContentMarks> new_marks =
      m_ContentMarksStack.top()->Clone();

  if (pProperty->IsName()) {
    ByteString property_name = pProperty->GetString();
    CPDF_Dictionary* pHolder = FindResourceHolder("Properties");
    if (!pHolder || !pHolder->GetDictFor(property_name))
      return;
    new_marks->AddMarkWithPropertiesHolder(tag, pHolder, property_name);
  } else if (pProperty->IsDictionary()) {
    new_marks->AddMarkWithDirectDict(tag, pProperty->AsDictionary());
  } else {
    return;
  }
  m_ContentMarksStack.push(std::move(new_marks));
}

void CPDF_StreamContentParser::Handle_BeginImage() {
  FX_FILESIZE savePos = m_pSyntax->GetPos();
  auto pDict = m_pDocument->New<CPDF_Dictionary>();
  while (1) {
    CPDF_StreamParser::SyntaxType type = m_pSyntax->ParseNextElement();
    if (type == CPDF_StreamParser::Keyword) {
      if (m_pSyntax->GetWord() != "ID") {
        m_pSyntax->SetPos(savePos);
        return;
      }
    }
    if (type != CPDF_StreamParser::Name) {
      break;
    }
    auto word = m_pSyntax->GetWord();
    ByteString key(word.Last(word.GetLength() - 1));
    auto pObj = m_pSyntax->ReadNextObject(false, false, 0);
    if (!key.IsEmpty()) {
      if (pObj && !pObj->IsInline()) {
        pDict->SetNewFor<CPDF_Reference>(key, m_pDocument.Get(),
                                         pObj->GetObjNum());
      } else {
        pDict->SetFor(key, std::move(pObj));
      }
    }
  }
  ReplaceAbbr(pDict.Get());
  CPDF_Object* pCSObj = nullptr;
  if (pDict->KeyExist("ColorSpace")) {
    pCSObj = pDict->GetDirectObjectFor("ColorSpace");
    if (pCSObj->IsName()) {
      ByteString name = pCSObj->GetString();
      if (name != "DeviceRGB" && name != "DeviceGray" && name != "DeviceCMYK") {
        pCSObj = FindResourceObj("ColorSpace", name);
        if (pCSObj && pCSObj->IsInline())
          pDict->SetFor("ColorSpace", pCSObj->Clone());
      }
    }
  }
  pDict->SetNewFor<CPDF_Name>("Subtype", "Image");
  RetainPtr<CPDF_Stream> pStream =
      m_pSyntax->ReadInlineStream(m_pDocument.Get(), std::move(pDict), pCSObj);
  while (1) {
    CPDF_StreamParser::SyntaxType type = m_pSyntax->ParseNextElement();
    if (type == CPDF_StreamParser::EndOfData) {
      break;
    }
    if (type != CPDF_StreamParser::Keyword) {
      continue;
    }
    if (m_pSyntax->GetWord() == "EI") {
      break;
    }
  }
  CPDF_ImageObject* pObj = AddImage(std::move(pStream));
  // Record the bounding box of this image, so rendering code can draw it
  // properly.
  if (pObj && pObj->GetImage()->IsMask())
    m_pObjectHolder->AddImageMaskBoundingBox(pObj->GetRect());
}

void CPDF_StreamContentParser::Handle_BeginMarkedContent() {
  std::unique_ptr<CPDF_ContentMarks> new_marks =
      m_ContentMarksStack.top()->Clone();
  new_marks->AddMark(GetString(0));
  m_ContentMarksStack.push(std::move(new_marks));
}

void CPDF_StreamContentParser::Handle_BeginText() {
  m_pCurStates->m_TextMatrix = CFX_Matrix();
  OnChangeTextMatrix();
  m_pCurStates->m_TextPos = CFX_PointF();
  m_pCurStates->m_TextLinePos = CFX_PointF();
}

void CPDF_StreamContentParser::Handle_CurveTo_123() {
  AddPathPoint(GetNumber(5), GetNumber(4), FXPT_TYPE::BezierTo, false);
  AddPathPoint(GetNumber(3), GetNumber(2), FXPT_TYPE::BezierTo, false);
  AddPathPoint(GetNumber(1), GetNumber(0), FXPT_TYPE::BezierTo, false);
}

void CPDF_StreamContentParser::Handle_ConcatMatrix() {
  CFX_Matrix new_matrix(GetNumber(5), GetNumber(4), GetNumber(3), GetNumber(2),
                        GetNumber(1), GetNumber(0));
  m_pCurStates->m_CTM = new_matrix * m_pCurStates->m_CTM;
  OnChangeTextMatrix();
}

void CPDF_StreamContentParser::Handle_SetColorSpace_Fill() {
  RetainPtr<CPDF_ColorSpace> pCS = FindColorSpace(GetString(0));
  if (!pCS)
    return;

  m_pCurStates->m_ColorState.GetMutableFillColor()->SetColorSpace(pCS);
}

void CPDF_StreamContentParser::Handle_SetColorSpace_Stroke() {
  RetainPtr<CPDF_ColorSpace> pCS = FindColorSpace(GetString(0));
  if (!pCS)
    return;

  m_pCurStates->m_ColorState.GetMutableStrokeColor()->SetColorSpace(pCS);
}

void CPDF_StreamContentParser::Handle_SetDash() {
  CPDF_Array* pArray = ToArray(GetObject(1));
  if (!pArray)
    return;

  m_pCurStates->SetLineDash(pArray, GetNumber(0), 1.0f);
}

void CPDF_StreamContentParser::Handle_SetCharWidth() {
  m_Type3Data[0] = GetNumber(1);
  m_Type3Data[1] = GetNumber(0);
  m_bColored = true;
}

void CPDF_StreamContentParser::Handle_SetCachedDevice() {
  for (int i = 0; i < 6; i++) {
    m_Type3Data[i] = GetNumber(5 - i);
  }
  m_bColored = false;
}

void CPDF_StreamContentParser::Handle_ExecuteXObject() {
  ByteString name = GetString(0);
  if (name == m_LastImageName && m_pLastImage && m_pLastImage->GetStream() &&
      m_pLastImage->GetStream()->GetObjNum()) {
    CPDF_ImageObject* pObj = AddImage(m_pLastImage);
    // Record the bounding box of this image, so rendering code can draw it
    // properly.
    if (pObj && pObj->GetImage()->IsMask())
      m_pObjectHolder->AddImageMaskBoundingBox(pObj->GetRect());
    return;
  }

  CPDF_Stream* pXObject = ToStream(FindResourceObj("XObject", name));
  if (!pXObject) {
    m_bResourceMissing = true;
    return;
  }

  ByteString type;
  if (pXObject->GetDict())
    type = pXObject->GetDict()->GetStringFor("Subtype");

  if (type == "Form") {
    AddForm(pXObject);
    return;
  }

  if (type == "Image") {
    CPDF_ImageObject* pObj = pXObject->IsInline()
                                 ? AddImage(ToStream(pXObject->Clone()))
                                 : AddImage(pXObject->GetObjNum());

    m_LastImageName = std::move(name);
    if (pObj) {
      m_pLastImage = pObj->GetImage();
      if (m_pLastImage->IsMask())
        m_pObjectHolder->AddImageMaskBoundingBox(pObj->GetRect());
    }
  }
}

void CPDF_StreamContentParser::AddForm(CPDF_Stream* pStream) {
  CPDF_AllStates status;
  status.m_GeneralState = m_pCurStates->m_GeneralState;
  status.m_GraphState = m_pCurStates->m_GraphState;
  status.m_ColorState = m_pCurStates->m_ColorState;
  status.m_TextState = m_pCurStates->m_TextState;
  auto form = std::make_unique<CPDF_Form>(
      m_pDocument.Get(), m_pPageResources.Get(), pStream, m_pResources.Get());
  form->ParseContent(&status, nullptr, m_ParsedSet.Get());

  CFX_Matrix matrix = m_pCurStates->m_CTM * m_mtContentToUser;

  auto pFormObj = std::make_unique<CPDF_FormObject>(GetCurrentStreamIndex(),
                                                    std::move(form), matrix);
  if (!m_pObjectHolder->BackgroundAlphaNeeded() &&
      pFormObj->form()->BackgroundAlphaNeeded()) {
    m_pObjectHolder->SetBackgroundAlphaNeeded(true);
  }
  pFormObj->CalcBoundingBox();
  SetGraphicStates(pFormObj.get(), true, true, true);
  m_pObjectHolder->AppendPageObject(std::move(pFormObj));
}

CPDF_ImageObject* CPDF_StreamContentParser::AddImage(
    RetainPtr<CPDF_Stream> pStream) {
  if (!pStream)
    return nullptr;

  auto pImageObj = std::make_unique<CPDF_ImageObject>(GetCurrentStreamIndex());
  pImageObj->SetImage(
      pdfium::MakeRetain<CPDF_Image>(m_pDocument.Get(), std::move(pStream)));

  return AddImageObject(std::move(pImageObj));
}

CPDF_ImageObject* CPDF_StreamContentParser::AddImage(uint32_t streamObjNum) {
  auto pImageObj = std::make_unique<CPDF_ImageObject>(GetCurrentStreamIndex());
  pImageObj->SetImage(CPDF_DocPageData::FromDocument(m_pDocument.Get())
                          ->GetImage(streamObjNum));

  return AddImageObject(std::move(pImageObj));
}

CPDF_ImageObject* CPDF_StreamContentParser::AddImage(
    const RetainPtr<CPDF_Image>& pImage) {
  if (!pImage)
    return nullptr;

  auto pImageObj = std::make_unique<CPDF_ImageObject>(GetCurrentStreamIndex());
  pImageObj->SetImage(CPDF_DocPageData::FromDocument(m_pDocument.Get())
                          ->GetImage(pImage->GetStream()->GetObjNum()));

  return AddImageObject(std::move(pImageObj));
}

CPDF_ImageObject* CPDF_StreamContentParser::AddImageObject(
    std::unique_ptr<CPDF_ImageObject> pImageObj) {
  SetGraphicStates(pImageObj.get(), pImageObj->GetImage()->IsMask(), false,
                   false);

  CFX_Matrix ImageMatrix = m_pCurStates->m_CTM * m_mtContentToUser;
  pImageObj->set_matrix(ImageMatrix);
  pImageObj->CalcBoundingBox();

  CPDF_ImageObject* pRet = pImageObj.get();
  m_pObjectHolder->AppendPageObject(std::move(pImageObj));
  return pRet;
}

std::vector<float> CPDF_StreamContentParser::GetColors() const {
  ASSERT(m_ParamCount > 0);
  return GetNumbers(m_ParamCount);
}

std::vector<float> CPDF_StreamContentParser::GetNamedColors() const {
  ASSERT(m_ParamCount > 0);
  const uint32_t nvalues = m_ParamCount - 1;
  std::vector<float> values(nvalues);
  for (size_t i = 0; i < nvalues; ++i)
    values[i] = GetNumber(m_ParamCount - i - 1);
  return values;
}

void CPDF_StreamContentParser::Handle_MarkPlace_Dictionary() {}

void CPDF_StreamContentParser::Handle_EndImage() {}

void CPDF_StreamContentParser::Handle_EndMarkedContent() {
  // First element is a sentinel, so do not pop it, ever. This may come up if
  // the EMCs are mismatched with the BMC/BDCs.
  if (m_ContentMarksStack.size() > 1)
    m_ContentMarksStack.pop();
}

void CPDF_StreamContentParser::Handle_EndText() {
  if (m_ClipTextList.empty())
    return;

  if (TextRenderingModeIsClipMode(m_pCurStates->m_TextState.GetTextMode()))
    m_pCurStates->m_ClipPath.AppendTexts(&m_ClipTextList);

  m_ClipTextList.clear();
}

void CPDF_StreamContentParser::Handle_FillPath() {
  AddPathObject(CFX_FillRenderOptions::FillType::kWinding, false);
}

void CPDF_StreamContentParser::Handle_FillPathOld() {
  AddPathObject(CFX_FillRenderOptions::FillType::kWinding, false);
}

void CPDF_StreamContentParser::Handle_EOFillPath() {
  AddPathObject(CFX_FillRenderOptions::FillType::kEvenOdd, false);
}

void CPDF_StreamContentParser::Handle_SetGray_Fill() {
  RetainPtr<CPDF_ColorSpace> pCS =
      CPDF_ColorSpace::GetStockCS(PDFCS_DEVICEGRAY);
  m_pCurStates->m_ColorState.SetFillColor(pCS, GetNumbers(1));
}

void CPDF_StreamContentParser::Handle_SetGray_Stroke() {
  RetainPtr<CPDF_ColorSpace> pCS =
      CPDF_ColorSpace::GetStockCS(PDFCS_DEVICEGRAY);
  m_pCurStates->m_ColorState.SetStrokeColor(pCS, GetNumbers(1));
}

void CPDF_StreamContentParser::Handle_SetExtendGraphState() {
  ByteString name = GetString(0);
  CPDF_Dictionary* pGS = ToDictionary(FindResourceObj("ExtGState", name));
  if (!pGS) {
    m_bResourceMissing = true;
    return;
  }
  m_pCurStates->ProcessExtGS(pGS, this);
}

void CPDF_StreamContentParser::Handle_ClosePath() {
  if (m_PathPoints.empty())
    return;

  if (m_PathStartX != m_PathCurrentX || m_PathStartY != m_PathCurrentY)
    AddPathPoint(m_PathStartX, m_PathStartY, FXPT_TYPE::LineTo, true);
  else if (m_PathPoints.back().m_Type != FXPT_TYPE::MoveTo)
    m_PathPoints.back().m_CloseFigure = true;
}

void CPDF_StreamContentParser::Handle_SetFlat() {
  m_pCurStates->m_GeneralState.SetFlatness(GetNumber(0));
}

void CPDF_StreamContentParser::Handle_BeginImageData() {}

void CPDF_StreamContentParser::Handle_SetLineJoin() {
  m_pCurStates->m_GraphState.SetLineJoin(
      static_cast<CFX_GraphStateData::LineJoin>(GetInteger(0)));
}

void CPDF_StreamContentParser::Handle_SetLineCap() {
  m_pCurStates->m_GraphState.SetLineCap(
      static_cast<CFX_GraphStateData::LineCap>(GetInteger(0)));
}

void CPDF_StreamContentParser::Handle_SetCMYKColor_Fill() {
  if (m_ParamCount != 4)
    return;

  RetainPtr<CPDF_ColorSpace> pCS =
      CPDF_ColorSpace::GetStockCS(PDFCS_DEVICECMYK);
  m_pCurStates->m_ColorState.SetFillColor(pCS, GetNumbers(4));
}

void CPDF_StreamContentParser::Handle_SetCMYKColor_Stroke() {
  if (m_ParamCount != 4)
    return;

  RetainPtr<CPDF_ColorSpace> pCS =
      CPDF_ColorSpace::GetStockCS(PDFCS_DEVICECMYK);
  m_pCurStates->m_ColorState.SetStrokeColor(pCS, GetNumbers(4));
}

void CPDF_StreamContentParser::Handle_LineTo() {
  if (m_ParamCount != 2)
    return;

  AddPathPoint(GetNumber(1), GetNumber(0), FXPT_TYPE::LineTo, false);
}

void CPDF_StreamContentParser::Handle_MoveTo() {
  if (m_ParamCount != 2)
    return;

  AddPathPoint(GetNumber(1), GetNumber(0), FXPT_TYPE::MoveTo, false);
  ParsePathObject();
}

void CPDF_StreamContentParser::Handle_SetMiterLimit() {
  m_pCurStates->m_GraphState.SetMiterLimit(GetNumber(0));
}

void CPDF_StreamContentParser::Handle_MarkPlace() {}

void CPDF_StreamContentParser::Handle_EndPath() {
  AddPathObject(CFX_FillRenderOptions::FillType::kNoFill, false);
}

void CPDF_StreamContentParser::Handle_SaveGraphState() {
  auto pStates = std::make_unique<CPDF_AllStates>();
  pStates->Copy(*m_pCurStates);
  m_StateStack.push_back(std::move(pStates));
}

void CPDF_StreamContentParser::Handle_RestoreGraphState() {
  if (m_StateStack.empty())
    return;
  std::unique_ptr<CPDF_AllStates> pStates = std::move(m_StateStack.back());
  m_StateStack.pop_back();
  m_pCurStates->Copy(*pStates);
}

void CPDF_StreamContentParser::Handle_Rectangle() {
  float x = GetNumber(3), y = GetNumber(2);
  float w = GetNumber(1), h = GetNumber(0);
  AddPathRect(x, y, w, h);
}

void CPDF_StreamContentParser::AddPathRect(float x, float y, float w, float h) {
  AddPathPoint(x, y, FXPT_TYPE::MoveTo, false);
  AddPathPoint(x + w, y, FXPT_TYPE::LineTo, false);
  AddPathPoint(x + w, y + h, FXPT_TYPE::LineTo, false);
  AddPathPoint(x, y + h, FXPT_TYPE::LineTo, false);
  AddPathPoint(x, y, FXPT_TYPE::LineTo, true);
}

void CPDF_StreamContentParser::Handle_SetRGBColor_Fill() {
  if (m_ParamCount != 3)
    return;

  RetainPtr<CPDF_ColorSpace> pCS = CPDF_ColorSpace::GetStockCS(PDFCS_DEVICERGB);
  m_pCurStates->m_ColorState.SetFillColor(pCS, GetNumbers(3));
}

void CPDF_StreamContentParser::Handle_SetRGBColor_Stroke() {
  if (m_ParamCount != 3)
    return;

  RetainPtr<CPDF_ColorSpace> pCS = CPDF_ColorSpace::GetStockCS(PDFCS_DEVICERGB);
  m_pCurStates->m_ColorState.SetStrokeColor(pCS, GetNumbers(3));
}

void CPDF_StreamContentParser::Handle_SetRenderIntent() {}

void CPDF_StreamContentParser::Handle_CloseStrokePath() {
  Handle_ClosePath();
  AddPathObject(CFX_FillRenderOptions::FillType::kNoFill, true);
}

void CPDF_StreamContentParser::Handle_StrokePath() {
  AddPathObject(CFX_FillRenderOptions::FillType::kNoFill, true);
}

void CPDF_StreamContentParser::Handle_SetColor_Fill() {
  int nargs = std::min(m_ParamCount, 4U);
  m_pCurStates->m_ColorState.SetFillColor(nullptr, GetNumbers(nargs));
}

void CPDF_StreamContentParser::Handle_SetColor_Stroke() {
  int nargs = std::min(m_ParamCount, 4U);
  m_pCurStates->m_ColorState.SetStrokeColor(nullptr, GetNumbers(nargs));
}

void CPDF_StreamContentParser::Handle_SetColorPS_Fill() {
  CPDF_Object* pLastParam = GetObject(0);
  if (!pLastParam)
    return;

  if (!pLastParam->IsName()) {
    m_pCurStates->m_ColorState.SetFillColor(nullptr, GetColors());
    return;
  }

  // A valid |pLastParam| implies |m_ParamCount| > 0, so GetNamedColors() call
  // below is safe.
  RetainPtr<CPDF_Pattern> pPattern = FindPattern(GetString(0), false);
  if (pPattern)
    m_pCurStates->m_ColorState.SetFillPattern(pPattern, GetNamedColors());
}

void CPDF_StreamContentParser::Handle_SetColorPS_Stroke() {
  CPDF_Object* pLastParam = GetObject(0);
  if (!pLastParam)
    return;

  if (!pLastParam->IsName()) {
    m_pCurStates->m_ColorState.SetStrokeColor(nullptr, GetColors());
    return;
  }

  // A valid |pLastParam| implies |m_ParamCount| > 0, so GetNamedColors() call
  // below is safe.
  RetainPtr<CPDF_Pattern> pPattern = FindPattern(GetString(0), false);
  if (pPattern)
    m_pCurStates->m_ColorState.SetStrokePattern(pPattern, GetNamedColors());
}

void CPDF_StreamContentParser::Handle_ShadeFill() {
  RetainPtr<CPDF_Pattern> pPattern = FindPattern(GetString(0), true);
  if (!pPattern)
    return;

  CPDF_ShadingPattern* pShading = pPattern->AsShadingPattern();
  if (!pShading)
    return;

  if (!pShading->IsShadingObject() || !pShading->Load())
    return;

  CFX_Matrix matrix = m_pCurStates->m_CTM * m_mtContentToUser;
  auto pObj = std::make_unique<CPDF_ShadingObject>(GetCurrentStreamIndex(),
                                                   pShading, matrix);
  SetGraphicStates(pObj.get(), false, false, false);
  CFX_FloatRect bbox =
      pObj->m_ClipPath.HasRef() ? pObj->m_ClipPath.GetClipBox() : m_BBox;
  if (pShading->IsMeshShading())
    bbox.Intersect(GetShadingBBox(pShading, pObj->matrix()));
  pObj->SetRect(bbox);
  m_pObjectHolder->AppendPageObject(std::move(pObj));
}

void CPDF_StreamContentParser::Handle_SetCharSpace() {
  m_pCurStates->m_TextState.SetCharSpace(GetNumber(0));
}

void CPDF_StreamContentParser::Handle_MoveTextPoint() {
  m_pCurStates->m_TextLinePos += CFX_PointF(GetNumber(1), GetNumber(0));
  m_pCurStates->m_TextPos = m_pCurStates->m_TextLinePos;
}

void CPDF_StreamContentParser::Handle_MoveTextPoint_SetLeading() {
  Handle_MoveTextPoint();
  m_pCurStates->m_TextLeading = -GetNumber(0);
}

void CPDF_StreamContentParser::Handle_SetFont() {
  float fs = GetNumber(0);
  if (fs == 0) {
    constexpr float kDefaultFontSize = 0.0f;
    fs = kDefaultFontSize;
  }

  m_pCurStates->m_TextState.SetFontSize(fs);
  RetainPtr<CPDF_Font> pFont = FindFont(GetString(1));
  if (pFont)
    m_pCurStates->m_TextState.SetFont(pFont);
}

CPDF_Dictionary* CPDF_StreamContentParser::FindResourceHolder(
    const ByteString& type) {
  if (!m_pResources)
    return nullptr;

  CPDF_Dictionary* pDict = m_pResources->GetDictFor(type);
  if (pDict)
    return pDict;

  if (m_pResources == m_pPageResources || !m_pPageResources)
    return nullptr;

  return m_pPageResources->GetDictFor(type);
}

CPDF_Object* CPDF_StreamContentParser::FindResourceObj(const ByteString& type,
                                                       const ByteString& name) {
  CPDF_Dictionary* pHolder = FindResourceHolder(type);
  return pHolder ? pHolder->GetDirectObjectFor(name) : nullptr;
}

RetainPtr<CPDF_Font> CPDF_StreamContentParser::FindFont(
    const ByteString& name) {
  CPDF_Dictionary* pFontDict = ToDictionary(FindResourceObj("Font", name));
  if (!pFontDict) {
    m_bResourceMissing = true;
    return CPDF_Font::GetStockFont(m_pDocument.Get(),
                                   CFX_Font::kDefaultAnsiFontName);
  }
  RetainPtr<CPDF_Font> pFont =
      CPDF_DocPageData::FromDocument(m_pDocument.Get())->GetFont(pFontDict);
  if (pFont && pFont->IsType3Font()) {
    pFont->AsType3Font()->SetPageResources(m_pResources.Get());
    pFont->AsType3Font()->CheckType3FontMetrics();
  }
  return pFont;
}

RetainPtr<CPDF_ColorSpace> CPDF_StreamContentParser::FindColorSpace(
    const ByteString& name) {
  if (name == "Pattern")
    return CPDF_ColorSpace::GetStockCS(PDFCS_PATTERN);

  if (name == "DeviceGray" || name == "DeviceCMYK" || name == "DeviceRGB") {
    ByteString defname = "Default";
    defname += name.Last(name.GetLength() - 7);
    const CPDF_Object* pDefObj = FindResourceObj("ColorSpace", defname);
    if (!pDefObj) {
      if (name == "DeviceGray")
        return CPDF_ColorSpace::GetStockCS(PDFCS_DEVICEGRAY);

      if (name == "DeviceRGB")
        return CPDF_ColorSpace::GetStockCS(PDFCS_DEVICERGB);

      return CPDF_ColorSpace::GetStockCS(PDFCS_DEVICECMYK);
    }
    return CPDF_DocPageData::FromDocument(m_pDocument.Get())
        ->GetColorSpace(pDefObj, nullptr);
  }
  const CPDF_Object* pCSObj = FindResourceObj("ColorSpace", name);
  if (!pCSObj) {
    m_bResourceMissing = true;
    return nullptr;
  }
  return CPDF_DocPageData::FromDocument(m_pDocument.Get())
      ->GetColorSpace(pCSObj, nullptr);
}

RetainPtr<CPDF_Pattern> CPDF_StreamContentParser::FindPattern(
    const ByteString& name,
    bool bShading) {
  CPDF_Object* pPattern =
      FindResourceObj(bShading ? "Shading" : "Pattern", name);
  if (!pPattern || (!pPattern->IsDictionary() && !pPattern->IsStream())) {
    m_bResourceMissing = true;
    return nullptr;
  }
  return CPDF_DocPageData::FromDocument(m_pDocument.Get())
      ->GetPattern(pPattern, bShading, m_pCurStates->m_ParentMatrix);
}

void CPDF_StreamContentParser::AddTextObject(const ByteString* pStrs,
                                             float fInitKerning,
                                             const std::vector<float>& kernings,
                                             size_t nSegs) {
  RetainPtr<CPDF_Font> pFont = m_pCurStates->m_TextState.GetFont();
  if (!pFont)
    return;

  if (fInitKerning != 0) {
    if (pFont->IsVertWriting())
      m_pCurStates->m_TextPos.y -= GetVerticalTextSize(fInitKerning);
    else
      m_pCurStates->m_TextPos.x -= GetHorizontalTextSize(fInitKerning);
  }
  if (nSegs == 0)
    return;

  const TextRenderingMode text_mode =
      pFont->IsType3Font() ? TextRenderingMode::MODE_FILL
                           : m_pCurStates->m_TextState.GetTextMode();
  {
    auto pText = std::make_unique<CPDF_TextObject>(GetCurrentStreamIndex());
    m_pLastTextObject = pText.get();
    SetGraphicStates(m_pLastTextObject.Get(), true, true, true);
    if (TextRenderingModeIsStrokeMode(text_mode)) {
      float* pCTM = pText->m_TextState.GetMutableCTM();
      pCTM[0] = m_pCurStates->m_CTM.a;
      pCTM[1] = m_pCurStates->m_CTM.c;
      pCTM[2] = m_pCurStates->m_CTM.b;
      pCTM[3] = m_pCurStates->m_CTM.d;
    }
    pText->SetSegments(pStrs, kernings, nSegs);
    pText->SetPosition(
        m_mtContentToUser.Transform(m_pCurStates->m_CTM.Transform(
            m_pCurStates->m_TextMatrix.Transform(CFX_PointF(
                m_pCurStates->m_TextPos.x,
                m_pCurStates->m_TextPos.y + m_pCurStates->m_TextRise)))));

    m_pCurStates->m_TextPos +=
        pText->CalcPositionData(m_pCurStates->m_TextHorzScale);
    if (TextRenderingModeIsClipMode(text_mode)) {
      m_ClipTextList.push_back(
          std::unique_ptr<CPDF_TextObject>(pText->Clone()));
    }
    m_pObjectHolder->AppendPageObject(std::move(pText));
  }
  if (!kernings.empty() && kernings[nSegs - 1] != 0) {
    if (pFont->IsVertWriting())
      m_pCurStates->m_TextPos.y -= GetVerticalTextSize(kernings[nSegs - 1]);
    else
      m_pCurStates->m_TextPos.x -= GetHorizontalTextSize(kernings[nSegs - 1]);
  }
}

float CPDF_StreamContentParser::GetHorizontalTextSize(float fKerning) const {
  return GetVerticalTextSize(fKerning) * m_pCurStates->m_TextHorzScale;
}

float CPDF_StreamContentParser::GetVerticalTextSize(float fKerning) const {
  return fKerning * m_pCurStates->m_TextState.GetFontSize() / 1000;
}

int32_t CPDF_StreamContentParser::GetCurrentStreamIndex() {
  auto it =
      std::upper_bound(m_StreamStartOffsets.begin(), m_StreamStartOffsets.end(),
                       m_pSyntax->GetPos() + m_StartParseOffset);
  return (it - m_StreamStartOffsets.begin()) - 1;
}

void CPDF_StreamContentParser::Handle_ShowText() {
  ByteString str = GetString(0);
  if (!str.IsEmpty())
    AddTextObject(&str, 0, std::vector<float>(), 1);
}

void CPDF_StreamContentParser::Handle_ShowText_Positioning() {
  CPDF_Array* pArray = ToArray(GetObject(0));
  if (!pArray)
    return;

  size_t n = pArray->size();
  size_t nsegs = 0;
  for (size_t i = 0; i < n; i++) {
    const CPDF_Object* pDirectObject = pArray->GetDirectObjectAt(i);
    if (pDirectObject && pDirectObject->IsString())
      nsegs++;
  }
  if (nsegs == 0) {
    for (size_t i = 0; i < n; i++) {
      float fKerning = pArray->GetNumberAt(i);
      if (fKerning != 0)
        m_pCurStates->m_TextPos.x -= GetHorizontalTextSize(fKerning);
    }
    return;
  }
  std::vector<ByteString> strs(nsegs);
  std::vector<float> kernings(nsegs);
  size_t iSegment = 0;
  float fInitKerning = 0;
  for (size_t i = 0; i < n; i++) {
    CPDF_Object* pObj = pArray->GetDirectObjectAt(i);
    if (!pObj)
      continue;

    if (pObj->IsString()) {
      ByteString str = pObj->GetString();
      if (str.IsEmpty())
        continue;
      strs[iSegment] = std::move(str);
      kernings[iSegment++] = 0;
    } else {
      float num = pObj->GetNumber();
      if (iSegment == 0)
        fInitKerning += num;
      else
        kernings[iSegment - 1] += num;
    }
  }
  AddTextObject(strs.data(), fInitKerning, kernings, iSegment);
}

void CPDF_StreamContentParser::Handle_SetTextLeading() {
  m_pCurStates->m_TextLeading = GetNumber(0);
}

void CPDF_StreamContentParser::Handle_SetTextMatrix() {
  m_pCurStates->m_TextMatrix =
      CFX_Matrix(GetNumber(5), GetNumber(4), GetNumber(3), GetNumber(2),
                 GetNumber(1), GetNumber(0));
  OnChangeTextMatrix();
  m_pCurStates->m_TextPos = CFX_PointF();
  m_pCurStates->m_TextLinePos = CFX_PointF();
}

void CPDF_StreamContentParser::OnChangeTextMatrix() {
  CFX_Matrix text_matrix(m_pCurStates->m_TextHorzScale, 0.0f, 0.0f, 1.0f, 0.0f,
                         0.0f);
  text_matrix.Concat(m_pCurStates->m_TextMatrix);
  text_matrix.Concat(m_pCurStates->m_CTM);
  text_matrix.Concat(m_mtContentToUser);
  float* pTextMatrix = m_pCurStates->m_TextState.GetMutableMatrix();
  pTextMatrix[0] = text_matrix.a;
  pTextMatrix[1] = text_matrix.c;
  pTextMatrix[2] = text_matrix.b;
  pTextMatrix[3] = text_matrix.d;
}

void CPDF_StreamContentParser::Handle_SetTextRenderMode() {
  TextRenderingMode mode;
  if (SetTextRenderingModeFromInt(GetInteger(0), &mode))
    m_pCurStates->m_TextState.SetTextMode(mode);
}

void CPDF_StreamContentParser::Handle_SetTextRise() {
  m_pCurStates->m_TextRise = GetNumber(0);
}

void CPDF_StreamContentParser::Handle_SetWordSpace() {
  m_pCurStates->m_TextState.SetWordSpace(GetNumber(0));
}

void CPDF_StreamContentParser::Handle_SetHorzScale() {
  if (m_ParamCount != 1) {
    return;
  }
  m_pCurStates->m_TextHorzScale = GetNumber(0) / 100;
  OnChangeTextMatrix();
}

void CPDF_StreamContentParser::Handle_MoveToNextLine() {
  m_pCurStates->m_TextLinePos.y -= m_pCurStates->m_TextLeading;
  m_pCurStates->m_TextPos = m_pCurStates->m_TextLinePos;
}

void CPDF_StreamContentParser::Handle_CurveTo_23() {
  AddPathPoint(m_PathCurrentX, m_PathCurrentY, FXPT_TYPE::BezierTo, false);
  AddPathPoint(GetNumber(3), GetNumber(2), FXPT_TYPE::BezierTo, false);
  AddPathPoint(GetNumber(1), GetNumber(0), FXPT_TYPE::BezierTo, false);
}

void CPDF_StreamContentParser::Handle_SetLineWidth() {
  m_pCurStates->m_GraphState.SetLineWidth(GetNumber(0));
}

void CPDF_StreamContentParser::Handle_Clip() {
  m_PathClipType = CFX_FillRenderOptions::FillType::kWinding;
}

void CPDF_StreamContentParser::Handle_EOClip() {
  m_PathClipType = CFX_FillRenderOptions::FillType::kEvenOdd;
}

void CPDF_StreamContentParser::Handle_CurveTo_13() {
  AddPathPoint(GetNumber(3), GetNumber(2), FXPT_TYPE::BezierTo, false);
  AddPathPoint(GetNumber(1), GetNumber(0), FXPT_TYPE::BezierTo, false);
  AddPathPoint(GetNumber(1), GetNumber(0), FXPT_TYPE::BezierTo, false);
}

void CPDF_StreamContentParser::Handle_NextLineShowText() {
  Handle_MoveToNextLine();
  Handle_ShowText();
}

void CPDF_StreamContentParser::Handle_NextLineShowText_Space() {
  m_pCurStates->m_TextState.SetWordSpace(GetNumber(2));
  m_pCurStates->m_TextState.SetCharSpace(GetNumber(1));
  Handle_NextLineShowText();
}

void CPDF_StreamContentParser::Handle_Invalid() {}

void CPDF_StreamContentParser::AddPathPoint(float x,
                                            float y,
                                            FXPT_TYPE type,
                                            bool close) {
  // If the path point is the same move as the previous one and neither of them
  // closes the path, then just skip it.
  if (!close && type == FXPT_TYPE::MoveTo && !m_PathPoints.empty() &&
      !m_PathPoints.back().m_CloseFigure &&
      m_PathPoints.back().m_Type == type && m_PathCurrentX == x &&
      m_PathCurrentY == y) {
    return;
  }

  m_PathCurrentX = x;
  m_PathCurrentY = y;
  if (type == FXPT_TYPE::MoveTo && !close) {
    m_PathStartX = x;
    m_PathStartY = y;
    if (!m_PathPoints.empty() &&
        m_PathPoints.back().IsTypeAndOpen(FXPT_TYPE::MoveTo)) {
      m_PathPoints.back().m_Point = CFX_PointF(x, y);
      return;
    }
  } else if (m_PathPoints.empty()) {
    return;
  }
  m_PathPoints.push_back(FX_PATHPOINT(CFX_PointF(x, y), type, close));
}

void CPDF_StreamContentParser::AddPathObject(
    CFX_FillRenderOptions::FillType fill_type,
    bool bStroke) {
  std::vector<FX_PATHPOINT> path_points;
  path_points.swap(m_PathPoints);
  CFX_FillRenderOptions::FillType path_clip_type = m_PathClipType;
  m_PathClipType = CFX_FillRenderOptions::FillType::kNoFill;

  if (path_points.empty())
    return;

  if (path_points.size() == 1) {
    if (path_clip_type != CFX_FillRenderOptions::FillType::kNoFill) {
      CPDF_Path path;
      path.AppendRect(0, 0, 0, 0);
      m_pCurStates->m_ClipPath.AppendPath(
          path, CFX_FillRenderOptions::FillType::kWinding, true);
    }
    return;
  }

  if (path_points.back().IsTypeAndOpen(FXPT_TYPE::MoveTo))
    path_points.pop_back();

  CPDF_Path path;
  for (const auto& point : path_points) {
    if (point.m_CloseFigure)
      path.AppendPointAndClose(point.m_Point, point.m_Type);
    else
      path.AppendPoint(point.m_Point, point.m_Type);
  }

  CFX_Matrix matrix = m_pCurStates->m_CTM * m_mtContentToUser;
  if (bStroke || fill_type != CFX_FillRenderOptions::FillType::kNoFill) {
    auto pPathObj = std::make_unique<CPDF_PathObject>(GetCurrentStreamIndex());
    pPathObj->set_stroke(bStroke);
    pPathObj->set_filltype(fill_type);
    pPathObj->path() = path;
    pPathObj->set_matrix(matrix);
    SetGraphicStates(pPathObj.get(), true, false, true);
    pPathObj->CalcBoundingBox();
    m_pObjectHolder->AppendPageObject(std::move(pPathObj));
  }
  if (path_clip_type != CFX_FillRenderOptions::FillType::kNoFill) {
    if (!matrix.IsIdentity())
      path.Transform(matrix);
    m_pCurStates->m_ClipPath.AppendPath(path, path_clip_type, true);
  }
}

uint32_t CPDF_StreamContentParser::Parse(
    const uint8_t* pData,
    uint32_t dwSize,
    uint32_t start_offset,
    uint32_t max_cost,
    const std::vector<uint32_t>& stream_start_offsets) {
  ASSERT(start_offset < dwSize);

  // Parsing will be done from |pDataStart|, for at most |size_left| bytes.
  const uint8_t* pDataStart = pData + start_offset;
  uint32_t size_left = dwSize - start_offset;

  m_StartParseOffset = start_offset;

  if (m_ParsedSet->size() > kMaxFormLevel ||
      pdfium::Contains(*m_ParsedSet, pDataStart)) {
    return size_left;
  }

  m_StreamStartOffsets = stream_start_offsets;

  pdfium::ScopedSetInsertion<const uint8_t*> scopedInsert(m_ParsedSet.Get(),
                                                          pDataStart);

  uint32_t init_obj_count = m_pObjectHolder->GetPageObjectCount();
  CPDF_StreamParser syntax(pdfium::make_span(pDataStart, size_left),
                           m_pDocument->GetByteStringPool());
  CPDF_StreamParserAutoClearer auto_clearer(&m_pSyntax, &syntax);
  while (1) {
    uint32_t cost = m_pObjectHolder->GetPageObjectCount() - init_obj_count;
    if (max_cost && cost >= max_cost) {
      break;
    }
    switch (syntax.ParseNextElement()) {
      case CPDF_StreamParser::EndOfData:
        return m_pSyntax->GetPos();
      case CPDF_StreamParser::Keyword:
        OnOperator(syntax.GetWord());
        ClearAllParams();
        break;
      case CPDF_StreamParser::Number:
        AddNumberParam(syntax.GetWord());
        break;
      case CPDF_StreamParser::Name: {
        auto word = syntax.GetWord();
        AddNameParam(word.Last(word.GetLength() - 1));
        break;
      }
      default:
        AddObjectParam(syntax.GetObject());
    }
  }
  return m_pSyntax->GetPos();
}

void CPDF_StreamContentParser::ParsePathObject() {
  float params[6] = {};
  int nParams = 0;
  int last_pos = m_pSyntax->GetPos();
  while (1) {
    CPDF_StreamParser::SyntaxType type = m_pSyntax->ParseNextElement();
    bool bProcessed = true;
    switch (type) {
      case CPDF_StreamParser::EndOfData:
        return;
      case CPDF_StreamParser::Keyword: {
        ByteStringView strc = m_pSyntax->GetWord();
        int len = strc.GetLength();
        if (len == 1) {
          switch (strc[0]) {
            case kPathOperatorSubpath:
              AddPathPoint(params[0], params[1], FXPT_TYPE::MoveTo, false);
              nParams = 0;
              break;
            case kPathOperatorLine:
              AddPathPoint(params[0], params[1], FXPT_TYPE::LineTo, false);
              nParams = 0;
              break;
            case kPathOperatorCubicBezier1:
              AddPathPoint(params[0], params[1], FXPT_TYPE::BezierTo, false);
              AddPathPoint(params[2], params[3], FXPT_TYPE::BezierTo, false);
              AddPathPoint(params[4], params[5], FXPT_TYPE::BezierTo, false);
              nParams = 0;
              break;
            case kPathOperatorCubicBezier2:
              AddPathPoint(m_PathCurrentX, m_PathCurrentY, FXPT_TYPE::BezierTo,
                           false);
              AddPathPoint(params[0], params[1], FXPT_TYPE::BezierTo, false);
              AddPathPoint(params[2], params[3], FXPT_TYPE::BezierTo, false);
              nParams = 0;
              break;
            case kPathOperatorCubicBezier3:
              AddPathPoint(params[0], params[1], FXPT_TYPE::BezierTo, false);
              AddPathPoint(params[2], params[3], FXPT_TYPE::BezierTo, false);
              AddPathPoint(params[2], params[3], FXPT_TYPE::BezierTo, false);
              nParams = 0;
              break;
            case kPathOperatorClosePath:
              Handle_ClosePath();
              nParams = 0;
              break;
            default:
              bProcessed = false;
              break;
          }
        } else if (len == 2) {
          if (strc[0] == kPathOperatorRectangle[0] &&
              strc[1] == kPathOperatorRectangle[1]) {
            AddPathRect(params[0], params[1], params[2], params[3]);
            nParams = 0;
          } else {
            bProcessed = false;
          }
        } else {
          bProcessed = false;
        }
        if (bProcessed) {
          last_pos = m_pSyntax->GetPos();
        }
        break;
      }
      case CPDF_StreamParser::Number: {
        if (nParams == 6)
          break;

        FX_Number number(m_pSyntax->GetWord());
        params[nParams++] = number.GetFloat();
        break;
      }
      default:
        bProcessed = false;
    }
    if (!bProcessed) {
      m_pSyntax->SetPos(last_pos);
      return;
    }
  }
}

// static
ByteStringView CPDF_StreamContentParser::FindKeyAbbreviationForTesting(
    ByteStringView abbr) {
  return FindFullName(kInlineKeyAbbr, pdfium::size(kInlineKeyAbbr), abbr);
}

// static
ByteStringView CPDF_StreamContentParser::FindValueAbbreviationForTesting(
    ByteStringView abbr) {
  return FindFullName(kInlineValueAbbr, pdfium::size(kInlineValueAbbr), abbr);
}

CPDF_StreamContentParser::ContentParam::ContentParam() {}

CPDF_StreamContentParser::ContentParam::~ContentParam() = default;
