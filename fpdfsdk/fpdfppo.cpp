// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "public/fpdf_ppo.h"

#include <map>
#include <memory>
#include <utility>
#include <vector>

#include "core/fpdfapi/page/cpdf_page.h"
#include "core/fpdfapi/page/cpdf_pageobject.h"
#include "core/fpdfapi/parser/cpdf_array.h"
#include "core/fpdfapi/parser/cpdf_document.h"
#include "core/fpdfapi/parser/cpdf_name.h"
#include "core/fpdfapi/parser/cpdf_number.h"
#include "core/fpdfapi/parser/cpdf_object.h"
#include "core/fpdfapi/parser/cpdf_reference.h"
#include "core/fpdfapi/parser/cpdf_stream.h"
#include "core/fpdfapi/parser/cpdf_stream_acc.h"
#include "core/fpdfapi/parser/cpdf_string.h"
#include "core/fxcrt/retain_ptr.h"
#include "core/fxcrt/unowned_ptr.h"
#include "fpdfsdk/fsdk_define.h"
#include "public/cpp/fpdf_deleters.h"
#include "third_party/base/ptr_util.h"
#include "third_party/base/stl_util.h"

namespace {

struct NupPageSettings {
  CFX_PointF point;
  float scale;
  CFX_RectF subPageRect;
};

/*
 * Calculates the N-up parameters.
 */
class NupState {
 public:
  explicit NupState(const double destPageWidth,
                    const double destPageHeight,
                    const unsigned int rows,
                    const unsigned int columns);

  void CalculateNewPagePosition(float inWidth,
                                float inHeight,
                                NupPageSettings* ret);

 private:
  size_t m_numPagesOnXAxis;
  size_t m_numPagesOnYAxis;
  float m_destPageWidth;
  float m_destPageHeight;
  float m_subPageWidth;
  float m_subPageHeight;

  size_t m_numPagesPerSheet;
  size_t m_subPage = 0;
  std::pair<size_t, size_t> ConvertPageOrder(size_t subPage) const;
  void CalculatePageEdit(size_t subx, size_t suby, NupPageSettings* ret) const;
};

NupState::NupState(const double destPageWidth,
                   const double destPageHeight,
                   const unsigned int rows,
                   const unsigned int columns)
    : m_numPagesOnXAxis(rows),
      m_numPagesOnYAxis(columns),
      m_destPageWidth(destPageWidth),
      m_destPageHeight(destPageHeight),
      m_numPagesPerSheet(rows * columns) {
  ASSERT((m_numPagesOnXAxis > 0) && (m_numPagesOnYAxis > 0));
  ASSERT((m_destPageWidth > 0) && (m_destPageHeight > 0));

  m_subPageWidth = m_destPageWidth / m_numPagesOnXAxis;
  m_subPageHeight = m_destPageHeight / m_numPagesOnYAxis;
}

std::pair<size_t, size_t> NupState::ConvertPageOrder(size_t subPage) const {
  size_t subX, subY;
  subX = subPage % m_numPagesOnXAxis;
  subY = subPage / m_numPagesOnXAxis;

  // Y Axis, pages start from the top of the output page.
  subY = m_numPagesOnYAxis - subY - 1;

  return {subX, subY};
}

void NupState::CalculatePageEdit(size_t subXPos,
                                 size_t subYPos,
                                 NupPageSettings* pageEdit) const {
  pageEdit->point.x = subXPos * m_subPageWidth;
  pageEdit->point.y = subYPos * m_subPageHeight;

  const float xScale = m_subPageWidth / pageEdit->subPageRect.width;
  const float yScale = m_subPageHeight / pageEdit->subPageRect.height;

  pageEdit->scale = std::min(xScale, yScale);

  float subWidth = pageEdit->subPageRect.width * pageEdit->scale;
  float subHeight = pageEdit->subPageRect.height * pageEdit->scale;
  if (xScale > yScale) {
    pageEdit->point.x += (m_subPageWidth - subWidth) / 2;
  } else {
    pageEdit->point.y += (m_subPageHeight - subHeight) / 2;
  }
}

void NupState::CalculateNewPagePosition(float inWidth,
                                        float inHeight,
                                        NupPageSettings* pageEdit) {
  if (m_subPage >= m_numPagesPerSheet)
    m_subPage = 0;

  pageEdit->subPageRect.width = inWidth;
  pageEdit->subPageRect.height = inHeight;

  size_t subX;
  size_t subY;
  std::tie(subX, subY) = ConvertPageOrder(m_subPage);
  CalculatePageEdit(subX, subY, pageEdit);
  ++m_subPage;
}

CPDF_Object* PageDictGetInheritableTag(CPDF_Dictionary* pDict,
                                       const ByteString& bsSrcTag) {
  if (!pDict || bsSrcTag.IsEmpty())
    return nullptr;
  if (!pDict->KeyExist("Parent") || !pDict->KeyExist("Type"))
    return nullptr;

  CPDF_Object* pType = pDict->GetObjectFor("Type")->GetDirect();
  if (!ToName(pType))
    return nullptr;
  if (pType->GetString().Compare("Page"))
    return nullptr;

  CPDF_Dictionary* pp =
      ToDictionary(pDict->GetObjectFor("Parent")->GetDirect());
  if (!pp)
    return nullptr;

  if (pDict->KeyExist(bsSrcTag))
    return pDict->GetObjectFor(bsSrcTag);

  while (pp) {
    if (pp->KeyExist(bsSrcTag))
      return pp->GetObjectFor(bsSrcTag);
    if (!pp->KeyExist("Parent"))
      break;
    pp = ToDictionary(pp->GetObjectFor("Parent")->GetDirect());
  }
  return nullptr;
}

CFX_FloatRect GetMediaBox(CPDF_Dictionary* pPageDict) {
  CPDF_Object* pMediaBox = PageDictGetInheritableTag(pPageDict, "MediaBox");
  CPDF_Array* pArray = ToArray(pMediaBox->GetDirect());
  if (!pArray)
    return CFX_FloatRect();

  return pArray->GetRect();
}

CFX_FloatRect GetCropBox(CPDF_Dictionary* pPageDict) {
  if (pPageDict->KeyExist("CropBox"))
    return pPageDict->GetRectFor("CropBox");
  return GetMediaBox(pPageDict);
}

CFX_FloatRect GetTrimBox(CPDF_Dictionary* pPageDict) {
  if (pPageDict->KeyExist("TrimBox"))
    return pPageDict->GetRectFor("TrimBox");
  return GetCropBox(pPageDict);
}

CPDF_Object* GetPageContent(CPDF_Dictionary* pPageDict) {
  return pPageDict ? pPageDict->GetDirectObjectFor("Contents") : nullptr;
}

bool CopyInheritable(CPDF_Dictionary* pCurPageDict,
                     CPDF_Dictionary* pSrcPageDict,
                     const ByteString& key) {
  if (pCurPageDict->KeyExist(key))
    return true;

  CPDF_Object* pInheritable = PageDictGetInheritableTag(pSrcPageDict, key);
  if (!pInheritable)
    return false;

  pCurPageDict->SetFor(key, pInheritable->Clone());
  return true;
}

bool ParserPageRangeString(ByteString rangstring,
                           int nCount,
                           std::vector<uint16_t>* pageArray) {
  if (rangstring.IsEmpty())
    return true;

  rangstring.Remove(' ');
  size_t nLength = rangstring.GetLength();
  ByteString cbCompareString("0123456789-,");
  for (size_t i = 0; i < nLength; ++i) {
    if (!cbCompareString.Contains(rangstring[i]))
      return false;
  }

  ByteString cbMidRange;
  size_t nStringFrom = 0;
  Optional<size_t> nStringTo = 0;
  while (nStringTo < nLength) {
    nStringTo = rangstring.Find(',', nStringFrom);
    if (!nStringTo.has_value())
      nStringTo = nLength;
    cbMidRange = rangstring.Mid(nStringFrom, nStringTo.value() - nStringFrom);
    auto nMid = cbMidRange.Find('-');
    if (!nMid.has_value()) {
      uint16_t pageNum =
          pdfium::base::checked_cast<uint16_t>(atoi(cbMidRange.c_str()));
      if (pageNum <= 0 || pageNum > nCount)
        return false;
      pageArray->push_back(pageNum);
    } else {
      uint16_t nStartPageNum = pdfium::base::checked_cast<uint16_t>(
          atoi(cbMidRange.Left(nMid.value()).c_str()));
      if (nStartPageNum == 0)
        return false;

      nMid = nMid.value() + 1;
      size_t nEnd = cbMidRange.GetLength() - nMid.value();
      if (nEnd == 0)
        return false;

      uint16_t nEndPageNum = pdfium::base::checked_cast<uint16_t>(
          atoi(cbMidRange.Mid(nMid.value(), nEnd).c_str()));
      if (nStartPageNum < 0 || nStartPageNum > nEndPageNum ||
          nEndPageNum > nCount) {
        return false;
      }
      for (uint16_t i = nStartPageNum; i <= nEndPageNum; ++i) {
        pageArray->push_back(i);
      }
    }
    nStringFrom = nStringTo.value() + 1;
  }
  return true;
}

bool GetPageNumbers(ByteString pageRange,
                    CPDF_Document* pSrcDoc,
                    std::vector<uint16_t>* pageArray) {
  uint16_t nCount = pSrcDoc->GetPageCount();
  if (!pageRange.IsEmpty()) {
    if (!ParserPageRangeString(pageRange, nCount, pageArray))
      return false;
  } else {
    for (uint16_t i = 1; i <= nCount; ++i) {
      pageArray->push_back(i);
    }
  }
  return true;
}

}  // namespace

class CPDF_PageOrganizer {
 public:
  CPDF_PageOrganizer(CPDF_Document* pDestPDFDoc, CPDF_Document* pSrcPDFDoc);
  ~CPDF_PageOrganizer();

  bool PDFDocInit();
  bool ExportPage(const std::vector<uint16_t>& pageNums, int nIndex);
  bool ExportNPagesToOne(const std::vector<uint16_t>& pageNums,
                         const double destPageWidth,
                         const double destPageHeight,
                         const unsigned int rows,
                         const unsigned int columns);
  void AddSubPage(CPDF_Dictionary* pPageDict,
                  CFX_PointF& position,
                  float scale,
                  ByteString* content);
  CPDF_Object* MakeXObject(CPDF_Dictionary* pSrcPageDict,
                           CPDF_Document* pDestDoc);
  void FinishPage(CPDF_Dictionary* pCurPageDict, const ByteString& content);
  void SetMediaBox(CPDF_Dictionary* pDectPageDict);

 private:
  using ObjectNumberMap = std::map<uint32_t, uint32_t>;

  bool UpdateReference(CPDF_Object* pObj, ObjectNumberMap* pObjNumberMap);
  uint32_t GetNewObjId(ObjectNumberMap* pObjNumberMap, CPDF_Reference* pRef);

  UnownedPtr<CPDF_Document> m_pDestPDFDoc;
  UnownedPtr<CPDF_Document> m_pSrcPDFDoc;
  uint32_t m_xobjectNum = 0;
  CFX_SizeF m_pageSize;
  // Key is XObject name
  std::map<ByteString, UnownedPtr<CPDF_Object>> m_xobjs;
};

CPDF_PageOrganizer::CPDF_PageOrganizer(CPDF_Document* pDestPDFDoc,
                                       CPDF_Document* pSrcPDFDoc)
    : m_pDestPDFDoc(pDestPDFDoc), m_pSrcPDFDoc(pSrcPDFDoc) {}

CPDF_PageOrganizer::~CPDF_PageOrganizer() {}

bool CPDF_PageOrganizer::PDFDocInit() {
  ASSERT(m_pDestPDFDoc);
  ASSERT(m_pSrcPDFDoc);

  CPDF_Dictionary* pNewRoot = m_pDestPDFDoc->GetRoot();
  if (!pNewRoot)
    return false;

  CPDF_Dictionary* pDocInfoDict = m_pDestPDFDoc->GetInfo();
  if (!pDocInfoDict)
    return false;

  CPDF_Dictionary* pSrcDict = m_pSrcPDFDoc->GetPage(0);
  if (!pSrcDict)
    return false;

  pDocInfoDict->SetNewFor<CPDF_String>("Producer", "PDFium", false);

  ByteString cbRootType = pNewRoot->GetStringFor("Type", "");
  if (cbRootType.IsEmpty())
    pNewRoot->SetNewFor<CPDF_Name>("Type", "Catalog");

  CPDF_Object* pElement = pNewRoot->GetObjectFor("Pages");
  CPDF_Dictionary* pNewPages =
      pElement ? ToDictionary(pElement->GetDirect()) : nullptr;
  if (!pNewPages) {
    pNewPages = m_pDestPDFDoc->NewIndirect<CPDF_Dictionary>();
    pNewRoot->SetNewFor<CPDF_Reference>("Pages", m_pDestPDFDoc.Get(),
                                        pNewPages->GetObjNum());
  }

  ByteString cbPageType = pNewPages->GetStringFor("Type", "");
  if (cbPageType.IsEmpty())
    pNewPages->SetNewFor<CPDF_Name>("Type", "Pages");

  if (!pNewPages->GetArrayFor("Kids")) {
    pNewPages->SetNewFor<CPDF_Number>("Count", 0);
    pNewPages->SetNewFor<CPDF_Reference>(
        "Kids", m_pDestPDFDoc.Get(),
        m_pDestPDFDoc->NewIndirect<CPDF_Array>()->GetObjNum());
  }

  return true;
}

void CPDF_PageOrganizer::AddSubPage(CPDF_Dictionary* pPageDict,
                                    CFX_PointF& position,
                                    float scale,
                                    ByteString* content) {
  ++m_xobjectNum;
  ByteString xobjectName = ByteString::Format("X%d", m_xobjectNum);

  CFX_Matrix matrix;
  matrix.Scale(scale, scale);
  matrix.Translate(position.x, position.y);

  m_xobjs[xobjectName] = MakeXObject(pPageDict, m_pDestPDFDoc.Get());

  std::ostringstream contentStream;
  contentStream << "q\n"
                << matrix.a << " " << matrix.b << " " << matrix.c << " "
                << matrix.d << " " << matrix.e << " " << matrix.f << " cm\n"
                << "/" << xobjectName << " Do Q\n";
  *content += ByteString(contentStream);
}

CPDF_Object* CPDF_PageOrganizer::MakeXObject(CPDF_Dictionary* pSrcPageDict,
                                             CPDF_Document* pDestDoc) {
  ASSERT(pSrcPageDict);

  auto pObjNumberMap = pdfium::MakeUnique<ObjectNumberMap>();

  CPDF_Object* pSrcContentObj = GetPageContent(pSrcPageDict);
  CPDF_Stream* pNewXObject = pDestDoc->NewIndirect<CPDF_Stream>(
      nullptr, 0,
      pdfium::MakeUnique<CPDF_Dictionary>(pDestDoc->GetByteStringPool()));
  CPDF_Dictionary* pNewXObjectDict = pNewXObject->GetDict();
  const ByteString resourceString = "Resources";
  if (!CopyInheritable(pNewXObjectDict, pSrcPageDict, resourceString)) {
    // Use a default empty resources if it does not exist.
    pNewXObjectDict->SetNewFor<CPDF_Dictionary>(resourceString);
  }
  CPDF_Dictionary* pSrcRes = pSrcPageDict->GetDictFor(resourceString);
  if (pSrcRes) {
    uint32_t dwSrcPageResourcesObj = pSrcRes->GetObjNum();
    uint32_t dwNewXobjectResourcesObj =
        pNewXObjectDict->GetDictFor(resourceString)->GetObjNum();
    (*pObjNumberMap)[dwSrcPageResourcesObj] = dwNewXobjectResourcesObj;
    CPDF_Dictionary* pNewXORes = pNewXObjectDict->GetDictFor(resourceString);
    UpdateReference(pNewXORes, pObjNumberMap.get());
  }

  pNewXObjectDict->SetNewFor<CPDF_Name>("Type", "XObject");
  pNewXObjectDict->SetNewFor<CPDF_Name>("Subtype", "Form");
  pNewXObjectDict->SetNewFor<CPDF_Number>("FormType", 1);
  CFX_FloatRect rcBBox = GetTrimBox(pSrcPageDict);
  pNewXObjectDict->SetRectFor("BBox", rcBBox);
  // TODO(xlou): add matrix field.
  CPDF_Stream* pStream;
  std::ostringstream textBuf;

  if (CPDF_Array* pSrcContentArray = ToArray(pSrcContentObj)) {
    ByteString srcContentStream;
    for (size_t i = 0; i < pSrcContentArray->GetCount(); i++) {
      pStream = pSrcContentArray->GetStreamAt(i);
      auto pAcc = pdfium::MakeRetain<CPDF_StreamAcc>(pStream);
      pAcc->LoadAllDataFiltered();
      ByteString sStream(pAcc->GetData(), pAcc->GetSize());
      srcContentStream += sStream;
      srcContentStream += "\n";
    }
    pNewXObject->SetDataAndRemoveFilter(srcContentStream.raw_str(),
                                        srcContentStream.GetLength());
  } else {
    pStream = pSrcContentObj->AsStream();
    auto pAcc = pdfium::MakeRetain<CPDF_StreamAcc>(pStream);
    pAcc->LoadAllDataFiltered();
    ByteString sStream(pAcc->GetData(), pAcc->GetSize());
    pNewXObject->SetDataAndRemoveFilter(sStream.raw_str(), sStream.GetLength());
  }

  return pNewXObject;
}

void CPDF_PageOrganizer::SetMediaBox(CPDF_Dictionary* pDestPageDict) {
  CPDF_Array* pArray = pDestPageDict->SetNewFor<CPDF_Array>("MediaBox");
  pArray->AddNew<CPDF_Number>(0);
  pArray->AddNew<CPDF_Number>(0);
  pArray->AddNew<CPDF_Number>(m_pageSize.width);
  pArray->AddNew<CPDF_Number>(m_pageSize.height);
}

bool CPDF_PageOrganizer::ExportPage(const std::vector<uint16_t>& pageNums,
                                    int nIndex) {
  int curpage = nIndex;
  auto pObjNumberMap = pdfium::MakeUnique<ObjectNumberMap>();
  for (size_t i = 0; i < pageNums.size(); ++i) {
    CPDF_Dictionary* pCurPageDict = m_pDestPDFDoc->CreateNewPage(curpage);
    CPDF_Dictionary* pSrcPageDict = m_pSrcPDFDoc->GetPage(pageNums[i] - 1);
    if (!pSrcPageDict || !pCurPageDict)
      return false;

    // Clone the page dictionary
    for (const auto& it : *pSrcPageDict) {
      const ByteString& cbSrcKeyStr = it.first;
      if (cbSrcKeyStr == "Type" || cbSrcKeyStr == "Parent")
        continue;

      CPDF_Object* pObj = it.second.get();
      pCurPageDict->SetFor(cbSrcKeyStr, pObj->Clone());
    }

    // inheritable item
    // Even though some entries are required by the PDF spec, there exist
    // PDFs that omit them. Set some defaults in this case.
    // 1 MediaBox - required
    if (!CopyInheritable(pCurPageDict, pSrcPageDict, "MediaBox")) {
      // Search for "CropBox" in the source page dictionary.
      // If it does not exist, use the default letter size.
      CPDF_Object* pInheritable =
          PageDictGetInheritableTag(pSrcPageDict, "CropBox");
      if (pInheritable) {
        pCurPageDict->SetFor("MediaBox", pInheritable->Clone());
      } else {
        // Make the default size letter size (8.5"x11")
        CPDF_Array* pArray = pCurPageDict->SetNewFor<CPDF_Array>("MediaBox");
        pArray->AddNew<CPDF_Number>(0);
        pArray->AddNew<CPDF_Number>(0);
        pArray->AddNew<CPDF_Number>(612);
        pArray->AddNew<CPDF_Number>(792);
      }
    }

    // 2 Resources - required
    if (!CopyInheritable(pCurPageDict, pSrcPageDict, "Resources")) {
      // Use a default empty resources if it does not exist.
      pCurPageDict->SetNewFor<CPDF_Dictionary>("Resources");
    }

    // 3 CropBox - optional
    CopyInheritable(pCurPageDict, pSrcPageDict, "CropBox");
    // 4 Rotate - optional
    CopyInheritable(pCurPageDict, pSrcPageDict, "Rotate");

    // Update the reference
    uint32_t dwOldPageObj = pSrcPageDict->GetObjNum();
    uint32_t dwNewPageObj = pCurPageDict->GetObjNum();
    (*pObjNumberMap)[dwOldPageObj] = dwNewPageObj;
    UpdateReference(pCurPageDict, pObjNumberMap.get());
    ++curpage;
  }

  return true;
}

void CPDF_PageOrganizer::FinishPage(CPDF_Dictionary* pCurPageDict,
                                    const ByteString& content) {
  ASSERT(pCurPageDict);

  CPDF_Dictionary* pRes = pCurPageDict->GetDictFor("Resources");
  if (!pRes)
    pRes = pCurPageDict->SetNewFor<CPDF_Dictionary>("Resources");

  CPDF_Dictionary* pPageXObject = pRes->GetDictFor("XObject");
  if (!pPageXObject)
    pPageXObject = pRes->SetNewFor<CPDF_Dictionary>("XObject");

  for (auto& it : m_xobjs) {
    CPDF_Object* pObj = it.second.Get();
    pPageXObject->SetNewFor<CPDF_Reference>(it.first, m_pDestPDFDoc.Get(),
                                            pObj->GetObjNum());
  }

  auto pDict = pdfium::MakeUnique<CPDF_Dictionary>(
      m_pDestPDFDoc.Get()->GetByteStringPool());
  CPDF_Stream* pStream = m_pDestPDFDoc.Get()->NewIndirect<CPDF_Stream>(
      nullptr, 0, std::move(pDict));
  pStream->SetData(content.raw_str(), content.GetLength());
  pCurPageDict->SetNewFor<CPDF_Reference>("Contents", m_pDestPDFDoc.Get(),
                                          pStream->GetObjNum());
  m_xobjs.clear();
}

bool CPDF_PageOrganizer::ExportNPagesToOne(
    const std::vector<uint16_t>& pageNums,
    const double destPageWidth,
    const double destPageHeight,
    const unsigned int rows,
    const unsigned int columns) {
  size_t numPagesPerSheet = rows * columns;

  if ((numPagesPerSheet <= 0) || (destPageWidth <= 0) ||
      (destPageHeight <= 0)) {
    return false;
  }

  if (numPagesPerSheet == 1)
    return ExportPage(pageNums, 0);

  m_pageSize.width = destPageWidth;
  m_pageSize.height = destPageHeight;

  NupState nupState(destPageWidth, destPageHeight, rows, columns);

  size_t curpage = 0;
  NupPageSettings pgEdit;
  for (size_t outerPage = 0; outerPage < pageNums.size();
       outerPage += numPagesPerSheet) {
    // Create a new page
    CPDF_Dictionary* pCurPageDict = m_pDestPDFDoc->CreateNewPage(curpage);
    if (!pCurPageDict)
      return false;

    SetMediaBox(pCurPageDict);
    ByteString content;
    size_t innerPageMax =
        std::min(outerPage + numPagesPerSheet, pageNums.size());
    for (size_t innerPage = outerPage; innerPage < innerPageMax; ++innerPage) {
      CPDF_Dictionary* pSrcPageDict =
          m_pSrcPDFDoc->GetPage(pageNums[innerPage] - 1);
      if (!pSrcPageDict)
        return false;

      CPDF_Page srcPage(m_pSrcPDFDoc.Get(), pSrcPageDict, true);
      nupState.CalculateNewPagePosition(srcPage.GetPageWidth(),
                                        srcPage.GetPageHeight(), &pgEdit);
      AddSubPage(pSrcPageDict, pgEdit.point, pgEdit.scale, &content);
    }

    // Finish up the current page.
    FinishPage(pCurPageDict, content);
    ++curpage;
  }

  return true;
}

bool CPDF_PageOrganizer::UpdateReference(CPDF_Object* pObj,
                                         ObjectNumberMap* pObjNumberMap) {
  switch (pObj->GetType()) {
    case CPDF_Object::REFERENCE: {
      CPDF_Reference* pReference = pObj->AsReference();
      uint32_t newobjnum = GetNewObjId(pObjNumberMap, pReference);
      if (newobjnum == 0)
        return false;
      pReference->SetRef(m_pDestPDFDoc.Get(), newobjnum);
      break;
    }
    case CPDF_Object::DICTIONARY: {
      CPDF_Dictionary* pDict = pObj->AsDictionary();
      auto it = pDict->begin();
      while (it != pDict->end()) {
        const ByteString& key = it->first;
        CPDF_Object* pNextObj = it->second.get();
        ++it;
        if (key == "Parent" || key == "Prev" || key == "First")
          continue;
        if (!pNextObj)
          return false;
        if (!UpdateReference(pNextObj, pObjNumberMap))
          pDict->RemoveFor(key);
      }
      break;
    }
    case CPDF_Object::ARRAY: {
      CPDF_Array* pArray = pObj->AsArray();
      for (size_t i = 0; i < pArray->GetCount(); ++i) {
        CPDF_Object* pNextObj = pArray->GetObjectAt(i);
        if (!pNextObj)
          return false;
        if (!UpdateReference(pNextObj, pObjNumberMap))
          return false;
      }
      break;
    }
    case CPDF_Object::STREAM: {
      CPDF_Stream* pStream = pObj->AsStream();
      CPDF_Dictionary* pDict = pStream->GetDict();
      if (!pDict)
        return false;
      if (!UpdateReference(pDict, pObjNumberMap))
        return false;
      break;
    }
    default:
      break;
  }

  return true;
}

uint32_t CPDF_PageOrganizer::GetNewObjId(ObjectNumberMap* pObjNumberMap,
                                         CPDF_Reference* pRef) {
  if (!pRef)
    return 0;

  uint32_t dwObjnum = pRef->GetRefObjNum();
  uint32_t dwNewObjNum = 0;
  const auto it = pObjNumberMap->find(dwObjnum);
  if (it != pObjNumberMap->end())
    dwNewObjNum = it->second;
  if (dwNewObjNum)
    return dwNewObjNum;

  CPDF_Object* pDirect = pRef->GetDirect();
  if (!pDirect)
    return 0;

  std::unique_ptr<CPDF_Object> pClone = pDirect->Clone();
  if (CPDF_Dictionary* pDictClone = pClone->AsDictionary()) {
    if (pDictClone->KeyExist("Type")) {
      ByteString strType = pDictClone->GetStringFor("Type");
      if (!FXSYS_stricmp(strType.c_str(), "Pages"))
        return 4;
      if (!FXSYS_stricmp(strType.c_str(), "Page"))
        return 0;
    }
  }
  CPDF_Object* pUnownedClone =
      m_pDestPDFDoc->AddIndirectObject(std::move(pClone));
  dwNewObjNum = pUnownedClone->GetObjNum();
  (*pObjNumberMap)[dwObjnum] = dwNewObjNum;
  if (!UpdateReference(pUnownedClone, pObjNumberMap))
    return 0;

  return dwNewObjNum;
}

FPDF_EXPORT FPDF_BOOL FPDF_CALLCONV FPDF_ImportPages(FPDF_DOCUMENT dest_doc,
                                                     FPDF_DOCUMENT src_doc,
                                                     FPDF_BYTESTRING pagerange,
                                                     int index) {
  CPDF_Document* pDestDoc = CPDFDocumentFromFPDFDocument(dest_doc);
  if (!dest_doc)
    return false;

  CPDF_Document* pSrcDoc = CPDFDocumentFromFPDFDocument(src_doc);
  if (!pSrcDoc)
    return false;

  std::vector<uint16_t> pageArray;
  if (!GetPageNumbers(pagerange, pSrcDoc, &pageArray))
    return false;

  CPDF_PageOrganizer pageOrg(pDestDoc, pSrcDoc);

  if (!pageOrg.PDFDocInit())
    return false;

  return pageOrg.ExportPage(pageArray, index);
}

FPDF_EXPORT FPDF_DOCUMENT FPDF_CALLCONV
FPDF_ImportNPagesToOne(FPDF_DOCUMENT src_doc,
                       const double output_width,
                       const double output_height,
                       const unsigned int rows,
                       const unsigned int columns) {
  std::unique_ptr<void, FPDFDocumentDeleter> output_doc(
      FPDF_CreateNewDocument());
  if (!output_doc.get())
    return nullptr;

  CPDF_Document* pDestDoc = CPDFDocumentFromFPDFDocument(output_doc.get());
  if (!pDestDoc)
    return nullptr;

  CPDF_Document* pSrcDoc = CPDFDocumentFromFPDFDocument(src_doc);
  if (!pSrcDoc)
    return nullptr;

  std::vector<uint16_t> pageArray;
  if (!GetPageNumbers(nullptr, pSrcDoc, &pageArray))
    return nullptr;

  CPDF_PageOrganizer pageOrg(pDestDoc, pSrcDoc);

  if ((!pageOrg.PDFDocInit()) ||
      (!pageOrg.ExportNPagesToOne(pageArray, output_width, output_height, rows,
                                  columns))) {
    return nullptr;
  }

  return output_doc.release();
}

FPDF_EXPORT FPDF_BOOL FPDF_CALLCONV
FPDF_CopyViewerPreferences(FPDF_DOCUMENT dest_doc, FPDF_DOCUMENT src_doc) {
  CPDF_Document* pDstDoc = CPDFDocumentFromFPDFDocument(dest_doc);
  if (!pDstDoc)
    return false;

  CPDF_Document* pSrcDoc = CPDFDocumentFromFPDFDocument(src_doc);
  if (!pSrcDoc)
    return false;

  CPDF_Dictionary* pSrcDict = pSrcDoc->GetRoot();
  pSrcDict = pSrcDict->GetDictFor("ViewerPreferences");
  if (!pSrcDict)
    return false;

  CPDF_Dictionary* pDstDict = pDstDoc->GetRoot();
  if (!pDstDict)
    return false;

  pDstDict->SetFor("ViewerPreferences", pSrcDict->CloneDirectObject());
  return true;
}
