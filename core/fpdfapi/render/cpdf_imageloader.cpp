// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fpdfapi/render/cpdf_imageloader.h"

#include "core/fpdfapi/page/cpdf_dibbase.h"
#include "core/fpdfapi/page/cpdf_image.h"
#include "core/fpdfapi/page/cpdf_imageobject.h"
#include "core/fpdfapi/page/cpdf_transferfunc.h"
#include "core/fpdfapi/render/cpdf_imagecacheentry.h"
#include "core/fpdfapi/render/cpdf_pagerendercache.h"
#include "core/fpdfapi/render/cpdf_renderstatus.h"
#include "core/fxge/dib/cfx_dibitmap.h"

CPDF_ImageLoader::CPDF_ImageLoader() = default;

CPDF_ImageLoader::~CPDF_ImageLoader() = default;

bool CPDF_ImageLoader::Start(CPDF_ImageObject* pImage,
                             CPDF_PageRenderCache* pCache,
                             bool bStdCS,
                             uint32_t GroupFamily,
                             bool bLoadMask,
                             CPDF_RenderStatus* pRenderStatus) {
  m_pCache = pCache;
  m_pImageObject = pImage;
  if (!m_pCache->StartGetCachedBitmap(m_pImageObject->GetImage(), bStdCS,
                                      GroupFamily, bLoadMask, pRenderStatus)) {
    HandleFailure();
    return false;
  }
  return true;
}

bool CPDF_ImageLoader::Continue(PauseIndicatorIface* pPause,
                                CPDF_RenderStatus* pRenderStatus) {
  if (!m_pCache->Continue(pPause, pRenderStatus)) {
    HandleFailure();
    return false;
  }
  return true;
}

RetainPtr<CFX_DIBBase> CPDF_ImageLoader::TranslateImage(
    const RetainPtr<CPDF_TransferFunc>& pTransferFunc) {
  ASSERT(pTransferFunc);
  ASSERT(!pTransferFunc->GetIdentity());

  m_pBitmap = pTransferFunc->TranslateImage(m_pBitmap);
  if (m_bCached && m_pMask)
    m_pMask = m_pMask->Clone(nullptr);
  m_bCached = false;
  return m_pBitmap;
}

void CPDF_ImageLoader::HandleFailure() {
  CPDF_ImageCacheEntry* entry = m_pCache->GetCurImageCacheEntry();
  m_bCached = true;
  m_pBitmap = entry->DetachBitmap();
  m_pMask = entry->DetachMask();
  m_MatteColor = entry->m_MatteColor;
}
