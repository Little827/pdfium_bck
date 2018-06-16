// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fpdfapi/parser/cpdf_obj_stream.h"

#include <utility>

#include "core/fpdfapi/parser/cpdf_dictionary.h"
#include "core/fpdfapi/parser/cpdf_number.h"
#include "core/fpdfapi/parser/cpdf_parser.h"
#include "core/fpdfapi/parser/cpdf_reference.h"
#include "core/fpdfapi/parser/cpdf_stream.h"
#include "core/fpdfapi/parser/cpdf_stream_acc.h"
#include "core/fxcrt/cfx_memorystream.h"

// static
bool CPDF_ObjStream::IsObjectsStreamObject(const CPDF_Object* object) {
  const CPDF_Stream* stream = ToStream(object);
  if (!stream)
    return false;

  const CPDF_Dictionary* stream_dict = stream->GetDict();
  if (!stream_dict)
    return false;

  if (stream_dict->GetStringFor("Type") != "ObjStm")
    return false;

  const CPDF_Number* number_of_objects =
      ToNumber(stream_dict->GetObjectFor("N"));
  if (!number_of_objects || !number_of_objects->IsInteger() ||
      number_of_objects->GetInteger() < 0 ||
      number_of_objects->GetInteger() >=
          static_cast<int>(CPDF_Parser::kMaxObjectNumber)) {
    return false;
  }

  const CPDF_Number* firtst_object_offset =
      ToNumber(stream_dict->GetObjectFor("First"));
  if (!firtst_object_offset || !firtst_object_offset->IsInteger() ||
      firtst_object_offset->GetInteger() < 0) {
    return false;
  }

  return true;
}

//  static
std::unique_ptr<CPDF_ObjStream> CPDF_ObjStream::Create(
    std::unique_ptr<CPDF_Stream> stream) {
  if (!IsObjectsStreamObject(stream.get()))
    return nullptr;

  return pdfium::WrapUnique(new CPDF_ObjStream(std::move(stream)));
}

CPDF_ObjStream::CPDF_ObjStream(std::unique_ptr<CPDF_Stream> obj_stream) {
  DCHECK(obj_stream);
  DCHECK(IsObjectsStreamObject(obj_stream.get()));
  Init(std::move(obj_stream));
}

CPDF_ObjStream::~CPDF_ObjStream() = default;

bool CPDF_ObjStream::HasObject(uint32_t obj_number) const {
  const auto it = objects_offsets_.find(obj_number);
  return it != objects_offsets_.end();
}

std::unique_ptr<CPDF_Object> CPDF_ObjStream::ParseObject(
    CPDF_IndirectObjectHolder* pObjList,
    uint32_t obj_number) const {
  const auto it = objects_offsets_.find(obj_number);
  if (it == objects_offsets_.end())
    return nullptr;

  auto result = ParseObjectAtOffset(pObjList, it->second);
  if (!result)
    return nullptr;

  result->SetObjNum(obj_number);
  return result;
}

std::vector<std::unique_ptr<CPDF_Object>> CPDF_ObjStream::ParseAllObjects(
    CPDF_IndirectObjectHolder* pObjList) const {
  std::vector<std::unique_ptr<CPDF_Object>> result;
  for (const auto objnum_and_offset : objects_offsets_) {
    auto object = ParseObjectAtOffset(pObjList, objnum_and_offset.second);
    if (object) {
      object->SetObjNum(objnum_and_offset.first);
      result.push_back(std::move(object));
    }
  }
  return result;
}

void CPDF_ObjStream::Init(std::unique_ptr<CPDF_Stream> stream) {
  obj_num_ = stream->GetObjNum();
  if (const auto* extends_ref =
          ToReference(stream->GetDict()->GetObjectFor("Extends"))) {
    extends_obj_num_ = extends_ref->GetRefObjNum();
  }

  // We should detach (or share) data from stream to reduce memory usage.
  if (stream->HasFilter()) {
    auto stream_acc = pdfium::MakeRetain<CPDF_StreamAcc>(stream.get());
    stream_acc->LoadAllDataFiltered();
    const uint32_t data_size = stream_acc->GetSize();
    data_stream_ = pdfium::MakeRetain<CFX_MemoryStream>(
        stream_acc->DetachData().release(), static_cast<size_t>(data_size),
        true);
  } else if (stream->IsMemoryBased()) {
    const uint32_t data_size = stream->GetRawSize();
    data_stream_ = pdfium::MakeRetain<CFX_MemoryStream>(
        stream->DetachMemoryBasedData().release(),
        static_cast<size_t>(data_size), true);
  } else {
    // Share file stream.
    data_stream_ = stream->FileStream();
  }

  first_object_offset_ = stream->GetDict()->GetIntegerFor("First");

  CPDF_SyntaxParser syntax;
  syntax.InitParser(data_stream_, 0);

  const int object_count = stream->GetDict()->GetIntegerFor("N");
  for (int32_t i = object_count; i > 0; --i) {
    if (syntax.GetPos() >= data_stream_->GetSize())
      break;

    const uint32_t obj_num = syntax.GetDirectNum();
    const uint32_t obj_offset = syntax.GetDirectNum();
    if (!obj_num)
      continue;

    objects_offsets_.insert(std::make_pair(obj_num, obj_offset));
  }
}

std::unique_ptr<CPDF_Object> CPDF_ObjStream::ParseObjectAtOffset(
    CPDF_IndirectObjectHolder* pObjList,
    uint32_t object_offset) const {
  FX_SAFE_FILESIZE offset_in_steam = first_object_offset_;
  offset_in_steam += object_offset;

  if (!offset_in_steam.IsValid())
    return nullptr;

  if (offset_in_steam.ValueOrDie() >= data_stream_->GetSize())
    return nullptr;

  CPDF_SyntaxParser syntax;
  syntax.InitParser(data_stream_, 0);
  syntax.SetPos(offset_in_steam.ValueOrDie());
  return syntax.GetObjectBody(pObjList);
}
