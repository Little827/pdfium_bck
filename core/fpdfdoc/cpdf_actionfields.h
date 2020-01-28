// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FPDFDOC_CPDF_ACTIONFIELDS_H_
#define CORE_FPDFDOC_CPDF_ACTIONFIELDS_H_

#include <stddef.h>

#include <vector>

#include "core/fpdfdoc/cpdf_action.h"
#include "core/fxcrt/unowned_ptr.h"

class CPDF_Object;

class CPDF_ActionFields {
 public:
  explicit CPDF_ActionFields(const CPDF_Action& action);
  ~CPDF_ActionFields();

  std::vector<const CPDF_Object*> GetAllFields() const;
  const CPDF_Object* GetField(size_t iIndex) const;

 private:
  const CPDF_Action m_Action;
};

#endif  // CORE_FPDFDOC_CPDF_ACTIONFIELDS_H_
