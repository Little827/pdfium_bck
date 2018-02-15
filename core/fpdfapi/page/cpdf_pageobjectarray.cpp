// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fpdfapi/page/cpdf_pageobjectarray.h"

#include <algorithm>
#include <utility>

CPDF_PageObjectArray::CPDF_PageObjectArray() {}

size_t CPDF_PageObjectArray::GetCount() {
  return m_PageObjects.size();
}

CPDF_PageObject* CPDF_PageObjectArray::GetObject(size_t index) {
  return m_PageObjects[index];
}

void CPDF_PageObjectArray::Add(CPDF_PageObject* obj) {
  m_PageObjects.push_back(obj);
}
