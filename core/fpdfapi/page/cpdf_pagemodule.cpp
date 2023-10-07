// Copyright 2016 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fpdfapi/page/cpdf_pagemodule.h"

#include "core/fpdfapi/font/cpdf_fontglobals.h"
#include "core/fpdfapi/page/cpdf_colorspace.h"
#include "core/fpdfapi/page/cpdf_streamcontentparser.h"

void InitializePageModule() {
  CPDF_ColorSpace::Initialize();
  CPDF_FontGlobals::Create();
  CPDF_FontGlobals::GetInstance()->LoadEmbeddedMaps();
  CPDF_StreamContentParser::Initialize();
}

void DestroyPageModule() {
  CPDF_StreamContentParser::Destroy();
  CPDF_FontGlobals::Destroy();
  CPDF_ColorSpace::Destroy();
}
