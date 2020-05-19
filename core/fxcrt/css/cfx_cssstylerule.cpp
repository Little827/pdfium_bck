// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/css/cfx_cssstylerule.h"

CFX_CSSStyleRule::CFX_CSSStyleRule() {}

CFX_CSSStyleRule::~CFX_CSSStyleRule() {}

size_t CFX_CSSStyleRule::CountSelectorLists() const {
  return selector_.size();
}

CFX_CSSSelector* CFX_CSSStyleRule::GetSelectorList(int32_t index) const {
  return selector_[index].get();
}

CFX_CSSDeclaration* CFX_CSSStyleRule::GetDeclaration() {
  return &declaration_;
}

void CFX_CSSStyleRule::SetSelector(
    std::vector<std::unique_ptr<CFX_CSSSelector>>* list) {
  ASSERT(selector_.empty());

  selector_.swap(*list);
}
