// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fpdfapi/edit/cpdf_pagecontentmanager.h"

#include "core/fpdfapi/parser/cpdf_array.h"
#include "core/fpdfapi/parser/cpdf_dictionary.h"
#include "core/fpdfapi/parser/cpdf_document.h"
#include "core/fpdfapi/parser/cpdf_reference.h"
#include "core/fpdfapi/parser/cpdf_stream.h"

CPDF_PageContentManager::CPDF_PageContentManager(
    CPDF_PageObjectHolder* obj_holder)
    : obj_holder_(obj_holder), doc_(obj_holder_->GetDocument()) {
  CPDF_Dictionary* pPageDict = obj_holder_->GetDict();

  CPDF_Object* pContent = pPageDict->GetObjectFor("Contents");
  CPDF_Array* pContentArray = ToArray(pContent);
  if (pContentArray) {
    contents_array_ = pContentArray;
    return;
  }

  CPDF_Reference* pReference = ToReference(pContent);
  if (pReference) {
    CPDF_Object* pIndirectObj = pReference->GetDirect();
    if (pIndirectObj) {
      pContentArray = pIndirectObj->AsArray();
      if (pContentArray) {
        contents_array_ = pContentArray;
      } else if (pIndirectObj->IsStream()) {
        contents_stream_ = pIndirectObj->AsStream();
      }
    }
  }
}

CPDF_Stream* CPDF_PageContentManager::GetStreamByIndex(int32_t stream_index) {
  if (contents_stream_)
    return stream_index == 0 ? contents_stream_.Get() : nullptr;

  if (contents_array_) {
    CPDF_Reference* pOldStreamRef =
        ToReference(contents_array_->GetObjectAt(stream_index));
    if (!pOldStreamRef)
      return nullptr;

    return pOldStreamRef->GetDirect()->AsStream();
  }

  return nullptr;
}

void CPDF_PageContentManager::AddStream(std::ostringstream* buf) {
  CPDF_Stream* new_stream = doc_->NewIndirect<CPDF_Stream>();
  new_stream->SetData(buf);

  // If there is one Content stream (not in an array), now there will be two, so
  // create an array with the old and the new one.
  if (contents_stream_) {
    CPDF_Array* pContentArray = doc_->NewIndirect<CPDF_Array>();
    pContentArray->AddNew<CPDF_Reference>(doc_.Get(),
                                          contents_stream_->GetObjNum());
    pContentArray->AddNew<CPDF_Reference>(doc_.Get(), new_stream->GetObjNum());

    CPDF_Dictionary* pPageDict = obj_holder_->GetDict();
    pPageDict->SetNewFor<CPDF_Reference>("Contents", doc_.Get(),
                                         pContentArray->GetObjNum());
    SetAsNewContents(pContentArray);
    contents_array_ = pContentArray;
    contents_stream_ = nullptr;
    return;
  }

  // If there is an array, just add the new stream to it.
  if (contents_array_) {
    contents_array_->AddNew<CPDF_Reference>(doc_.Get(),
                                            new_stream->GetObjNum());
    return;
  }

  // There were no Contents, so add the new stream as the single Content stream.
  SetAsNewContents(new_stream);
  contents_stream_ = new_stream;
}

void CPDF_PageContentManager::SetAsNewContents(CPDF_Object* obj) {
  CPDF_Dictionary* pPageDict = obj_holder_->GetDict();
  pPageDict->SetNewFor<CPDF_Reference>("Contents", doc_.Get(),
                                       obj->GetObjNum());
}
