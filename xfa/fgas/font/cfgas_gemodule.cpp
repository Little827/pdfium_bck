// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "xfa/fgas/font/cfgas_gemodule.h"

#include "xfa/fgas/font/cfgas_fontmgr.h"

namespace {

CFGAS_GEModule* g_pGEModule = nullptr;

}  // namespace

// static
void CFGAS_GEModule::Create() {
  ASSERT(!g_pGEModule);
  g_pGEModule = new CFGAS_GEModule();
  g_pGEModule->GetFontMgr()->EnumFonts();
}

// static
void CFGAS_GEModule::Destroy() {
  ASSERT(g_pGEModule);
  delete g_pGEModule;
  g_pGEModule = nullptr;
}

// static
CFGAS_GEModule* CFGAS_GEModule::Get() {
  ASSERT(g_pGEModule);
  return g_pGEModule;
}

CFGAS_GEModule::CFGAS_GEModule()
    : font_mgr_(std::make_unique<CFGAS_FontMgr>()) {}

CFGAS_GEModule::~CFGAS_GEModule() = default;
