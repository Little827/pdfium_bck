// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FPDFAPI_EDIT_CPDF_PAGECONTENTMANAGER_H_
#define CORE_FPDFAPI_EDIT_CPDF_PAGECONTENTMANAGER_H_

#include <sstream>

#include "core/fxcrt/unowned_ptr.h"

class CPDF_Array;
class CPDF_Document;
class CPDF_Object;
class CPDF_Stream;
class CPDF_PageObjectHolder;

class CPDF_PageContentManager {
 public:
  explicit CPDF_PageContentManager(CPDF_PageObjectHolder* pObjHolder);
  ~CPDF_PageContentManager() = default;
  CPDF_Stream* GetStreamByIndex(int32_t stream_index);
  void AddStream(std::ostringstream* buf);

 private:
  void SetAsNewContents(CPDF_Object* obj);

  UnownedPtr<CPDF_PageObjectHolder> const obj_holder_;
  UnownedPtr<CPDF_Document> const doc_;
  UnownedPtr<CPDF_Array> contents_array_;
  UnownedPtr<CPDF_Stream> contents_stream_;
};

#endif  // CORE_FPDFAPI_EDIT_CPDF_PAGECONTENTMANAGER_H_
