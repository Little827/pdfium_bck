// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxge/cfx_gemodule.h"

#include "core/fxge/cfx_folderfontinfo.h"
#include "core/fxge/cfx_fontcache.h"
#include "core/fxge/cfx_fontmgr.h"
#include "third_party/base/ptr_util.h"

namespace {

// Automatic destruction when thread exits, which means the main program must
// wait for all threads to finish before calling FPDF_DestroyLibrary().
thread_local std::unique_ptr<CFX_GEModule> g_pGEModule;

}  // namespace

// static
const char** CFX_GEModule::s_pUserFontPaths = nullptr;

CFX_GEModule::CFX_GEModule()
    : m_pFontMgr(pdfium::MakeUnique<CFX_FontMgr>()), m_pPlatformData(nullptr) {}

CFX_GEModule::~CFX_GEModule() {
  DestroyPlatform();
}

// static
CFX_GEModule* CFX_GEModule::Get() {
  if (!g_pGEModule) {
    g_pGEModule = pdfium::MakeUnique<CFX_GEModule>();
    g_pGEModule->InitPlatform();
  }
  return g_pGEModule.get();
}

// static
void CFX_GEModule::Destroy() {
  ASSERT(g_pGEModule);
  g_pGEModule.reset();
}

// static
void CFX_GEModule::SetUserFontPaths(const char** pUserFontPaths) {
  s_pUserFontPaths = pUserFontPaths;
}

CFX_FontCache* CFX_GEModule::GetFontCache() {
  if (!m_pFontCache)
    m_pFontCache = pdfium::MakeUnique<CFX_FontCache>();
  return m_pFontCache.get();
}
