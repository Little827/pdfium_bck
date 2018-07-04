// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fpdfapi/page/cpdf_contentmark.h"

#include <utility>

#include "core/fpdfapi/parser/cpdf_dictionary.h"

CPDF_ContentMark::CPDF_ContentMark() {}

CPDF_ContentMark::~CPDF_ContentMark() {}

std::unique_ptr<CPDF_ContentMark> CPDF_ContentMark::Clone() {
  auto result = pdfium::MakeUnique<CPDF_ContentMark>();
  if (m_MarkData)
    result->m_MarkData.Reset(new MarkData(*m_MarkData));

  return result;
}

size_t CPDF_ContentMark::CountItems() const {
  if (!m_MarkData)
    return 0;

  return m_MarkData->CountItems();
}

CPDF_ContentMarkItem* CPDF_ContentMark::GetItem(size_t i) {
  ASSERT(i < CountItems());
  return m_MarkData->GetItem(i);
}

int CPDF_ContentMark::GetMarkedContentID() const {
  if (!m_MarkData)
    return -1;

  return m_MarkData->GetMarkedContentID();
}

void CPDF_ContentMark::AddMark(ByteString name,
                               CPDF_Dictionary* pDict,
                               bool bDirect) {
  if (!m_MarkData)
    m_MarkData.Reset(new MarkData());

  m_MarkData->AddMark(std::move(name), pDict, bDirect);
}

void CPDF_ContentMark::DeleteLastMark() {
  if (!m_MarkData)
    return;

  m_MarkData->DeleteLastMark();
  if (CountItems() == 0)
    m_MarkData.Reset();
}

CPDF_ContentMark::MarkData::MarkData() {}

CPDF_ContentMark::MarkData::MarkData(const MarkData& src)
    : m_Marks(src.m_Marks) {}

CPDF_ContentMark::MarkData::~MarkData() {}

size_t CPDF_ContentMark::MarkData::CountItems() const {
  return m_Marks.size();
}

CPDF_ContentMarkItem* CPDF_ContentMark::MarkData::GetItem(size_t index) {
  return m_Marks[index].Get();
}

int CPDF_ContentMark::MarkData::GetMarkedContentID() const {
  for (const auto& pMark : m_Marks) {
    const CPDF_Dictionary* pDict = pMark->GetParam();
    if (pDict && pDict->KeyExist("MCID"))
      return pDict->GetIntegerFor("MCID");
  }
  return -1;
}

void CPDF_ContentMark::MarkData::AddMark(ByteString name,
                                         CPDF_Dictionary* pDict,
                                         bool bDirect) {
  auto pItem = pdfium::MakeRetain<CPDF_ContentMarkItem>();
  pItem->SetName(std::move(name));
  if (pDict) {
    if (bDirect)
      pItem->SetDirectDict(ToDictionary(pDict->Clone()));
    else
      pItem->SetPropertiesDict(pDict);
  }
  m_Marks.push_back(pItem);
}

void CPDF_ContentMark::MarkData::DeleteLastMark() {
  if (!m_Marks.empty())
    m_Marks.pop_back();
}
