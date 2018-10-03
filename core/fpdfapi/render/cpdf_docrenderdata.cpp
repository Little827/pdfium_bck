// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fpdfapi/render/cpdf_docrenderdata.h"

#include <array>
#include <memory>
#include <utility>

#include "core/fpdfapi/font/cpdf_type3font.h"
#include "core/fpdfapi/page/cpdf_function.h"
#include "core/fpdfapi/parser/cpdf_array.h"
#include "core/fpdfapi/parser/cpdf_document.h"
#include "core/fpdfapi/render/cpdf_dibbase.h"
#include "core/fpdfapi/render/cpdf_transferfunc.h"
#include "core/fpdfapi/render/cpdf_type3cache.h"

namespace {

const int kMaxOutputs = 16;

}  // namespace

CPDF_DocRenderData::CPDF_DocRenderData(CPDF_Document* pPDFDoc)
    : m_pPDFDoc(pPDFDoc) {}

CPDF_DocRenderData::~CPDF_DocRenderData() {
  Clear(true);
}

RetainPtr<CPDF_Type3Cache> CPDF_DocRenderData::GetCachedType3(
    CPDF_Type3Font* pFont) {
  auto it = m_Type3FaceMap.find(pFont);
  if (it != m_Type3FaceMap.end())
    return it->second;

  auto pCache = pdfium::MakeRetain<CPDF_Type3Cache>(pFont);
  m_Type3FaceMap[pFont] = pCache;
  return pCache;
}

void CPDF_DocRenderData::MaybePurgeCachedType3(CPDF_Type3Font* pFont) {
  auto it = m_Type3FaceMap.find(pFont);
  if (it != m_Type3FaceMap.end() && it->second->HasOneRef())
    m_Type3FaceMap.erase(it);
}

RetainPtr<CPDF_TransferFunc> CPDF_DocRenderData::GetTransferFunc(
    const CPDF_Object* pObj) {
  if (!pObj)
    return nullptr;

  auto it = m_TransferFuncMap.find(pObj);
  if (it != m_TransferFuncMap.end())
    return it->second;

  m_TransferFuncMap[pObj] = CreateTransferFunc(pObj);
  return m_TransferFuncMap[pObj];
}

void CPDF_DocRenderData::MaybePurgeTransferFunc(const CPDF_Object* pObj) {
  auto it = m_TransferFuncMap.find(pObj);
  if (it != m_TransferFuncMap.end() && it->second->HasOneRef())
    m_TransferFuncMap.erase(it);
}

void CPDF_DocRenderData::Clear(bool bRelease) {
  for (auto it = m_Type3FaceMap.begin(); it != m_Type3FaceMap.end();) {
    auto curr_it = it++;
    if (bRelease || curr_it->second->HasOneRef()) {
      m_Type3FaceMap.erase(curr_it);
    }
  }

  for (auto it = m_TransferFuncMap.begin(); it != m_TransferFuncMap.end();) {
    auto curr_it = it++;
    if (bRelease || curr_it->second->HasOneRef())
      m_TransferFuncMap.erase(curr_it);
  }
}

RetainPtr<CPDF_TransferFunc> CPDF_DocRenderData::CreateTransferFunc(
    const CPDF_Object* pObj) const {
  const CPDF_Array* pArray = pObj->AsArray();
  if (pArray)
    return CreateTransferFuncFromArray(pArray);
  return CreateTransferFuncFromNonArray(pObj);
}

RetainPtr<CPDF_TransferFunc> CPDF_DocRenderData::CreateTransferFuncFromNonArray(
    const CPDF_Object* pObj) const {
  ASSERT(pObj);
  ASSERT(!pObj->IsArray());

  std::unique_ptr<CPDF_Function> pFunc = CPDF_Function::Load(pObj);
  if (!pFunc)
    return nullptr;

  bool bIdentity = true;
  std::array<uint8_t, CPDF_TransferFunc::kSampleSize> samples;
  float input;
  int noutput;
  float output[kMaxOutputs];
  memset(output, 0, sizeof(output));
  for (int v = 0; v < 256; ++v) {
    input = static_cast<float>(v) / 255.0f;
    if (pFunc->CountOutputs() <= kMaxOutputs)
      pFunc->Call(&input, 1, output, &noutput);
    int o = FXSYS_round(output[0] * 255);
    if (o != v)
      bIdentity = false;
    for (int i = 0; i < 3; ++i)
      samples[i * 256 + v] = o;
    continue;
  }

  return pdfium::MakeRetain<CPDF_TransferFunc>(m_pPDFDoc.Get(), bIdentity,
                                               std::move(samples));
}

RetainPtr<CPDF_TransferFunc> CPDF_DocRenderData::CreateTransferFuncFromArray(
    const CPDF_Array* pArray) const {
  ASSERT(pArray);

  std::unique_ptr<CPDF_Function> pFuncs[3];
  if (pArray->GetCount() < 3)
    return nullptr;

  for (uint32_t i = 0; i < 3; ++i) {
    pFuncs[2 - i] = CPDF_Function::Load(pArray->GetDirectObjectAt(i));
    if (!pFuncs[2 - i])
      return nullptr;
  }

  bool bIdentity = true;
  std::array<uint8_t, CPDF_TransferFunc::kSampleSize> samples;
  float input;
  int noutput;
  float output[kMaxOutputs];
  memset(output, 0, sizeof(output));
  for (int v = 0; v < 256; ++v) {
    input = static_cast<float>(v) / 255.0f;
    for (int i = 0; i < 3; ++i) {
      if (pFuncs[i]->CountOutputs() > kMaxOutputs) {
        samples[i * 256 + v] = v;
        continue;
      }
      pFuncs[i]->Call(&input, 1, output, &noutput);
      int o = FXSYS_round(output[0] * 255);
      if (o != v)
        bIdentity = false;
      samples[i * 256 + v] = o;
    }
  }

  return pdfium::MakeRetain<CPDF_TransferFunc>(m_pPDFDoc.Get(), bIdentity,
                                               std::move(samples));
}
