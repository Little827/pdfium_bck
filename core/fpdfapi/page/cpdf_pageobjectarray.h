// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FPDFAPI_PAGE_CPDF_PAGEOBJECTARRAY_H_
#define CORE_FPDFAPI_PAGE_CPDF_PAGEOBJECTARRAY_H_

#include <memory>
#include <vector>

#include "core/fpdfapi/page/cpdf_pageobject.h"
#include "core/fxcrt/fx_string.h"
#include "core/fxcrt/fx_system.h"

class CPDF_PageObjectArray {
 public:
  CPDF_PageObjectArray();

  size_t GetCount();
  CPDF_PageObject* GetObject(size_t index);
  void Add(CPDF_PageObject* obj);

 private:
  std::vector<CPDF_PageObject*> m_PageObjects;
};

#endif  // CORE_FPDFAPI_PAGE_CPDF_PAGEOBJECTARRAY_H_
