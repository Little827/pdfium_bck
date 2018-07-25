// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fpdfapi/parser/cpdf_cross_ref_parser.h"

#include <utility>
#include <vector>

#include "core/fpdfapi/parser/cpdf_array.h"
#include "core/fpdfapi/parser/cpdf_cross_ref_table.h"
#include "core/fpdfapi/parser/cpdf_dictionary.h"
#include "core/fpdfapi/parser/cpdf_number.h"
#include "core/fpdfapi/parser/cpdf_object_stream.h"
#include "core/fpdfapi/parser/cpdf_parser.h"
#include "core/fpdfapi/parser/cpdf_read_validator.h"
#include "core/fpdfapi/parser/cpdf_stream.h"
#include "core/fpdfapi/parser/cpdf_stream_acc.h"
#include "core/fpdfapi/parser/cpdf_syntax_parser.h"

namespace {

enum CrossRefStreamObjType : uint32_t {
  kFree = 0x00,
  kNormal = 0x01,
  kCompressed = 0x02,
};

uint32_t GetVarInt(const uint8_t* p, int32_t n) {
  uint32_t result = 0;
  for (int32_t i = 0; i < n; ++i)
    result = result * 256 + p[i];
  return result;
}

}  // namespace

CPDF_CrossRefParser::CPDF_CrossRefParser(CPDF_SyntaxParser* syntax)
    : syntax_(syntax) {
  ASSERT(syntax);
}

CPDF_CrossRefParser::~CPDF_CrossRefParser() = default;

std::unique_ptr<CPDF_CrossRefTable> CPDF_CrossRefParser::RebuildCrossRef() {
  if (!GetValidator()->CheckWholeFileAndRequestIfUnavailable())
    return nullptr;

  auto cross_ref_table = pdfium::MakeUnique<CPDF_CrossRefTable>();

  const uint32_t kBufferSize = 4096;
  syntax_->SetReadBufferSize(kBufferSize);
  syntax_->SetPos(0);

  bool is_number;
  std::vector<std::pair<uint32_t, FX_FILESIZE>> numbers;
  for (ByteString word = syntax_->GetNextWord(&is_number); !word.IsEmpty();
       word = syntax_->GetNextWord(&is_number)) {
    if (is_number) {
      numbers.emplace_back(FXSYS_atoui(word.c_str()),
                           syntax_->GetPos() - word.GetLength());
      if (numbers.size() > 2u)
        numbers.erase(numbers.begin());
      continue;
    }

    if (word == "(") {
      syntax_->ReadString();
    } else if (word == "<") {
      syntax_->ReadHexString();
    } else if (word == "trailer") {
      std::unique_ptr<CPDF_Object> trailer = syntax_->GetObjectBody(nullptr);
      if (trailer) {
        cross_ref_table = CPDF_CrossRefTable::MergeUp(
            std::move(cross_ref_table),
            pdfium::MakeUnique<CPDF_CrossRefTable>(ToDictionary(
                trailer->IsStream() ? trailer->AsStream()->GetDict()->Clone()
                                    : std::move(trailer))));
      }
    } else if (word == "obj" && numbers.size() == 2u) {
      const FX_FILESIZE obj_pos = numbers[0].second;
      const uint32_t obj_num = numbers[0].first;
      const uint32_t gen_num = numbers[1].first;

      syntax_->SetPos(obj_pos);
      const std::unique_ptr<CPDF_Stream> stream =
          ToStream(syntax_->GetIndirectObject(
              nullptr, CPDF_SyntaxParser::ParseType::kStrict));

      if (stream && stream->GetDict()->GetStringFor("Type") == "XRef") {
        cross_ref_table = CPDF_CrossRefTable::MergeUp(
            std::move(cross_ref_table),
            pdfium::MakeUnique<CPDF_CrossRefTable>(
                ToDictionary(stream->GetDict()->Clone())));
      }

      if (obj_num < CPDF_Parser::kMaxObjectNumber) {
        cross_ref_table->AddNormal(obj_num, gen_num, obj_pos);
        if (const auto object_stream =
                CPDF_ObjectStream::Create(stream.get())) {
          for (const auto& it : object_stream->objects_offsets()) {
            if (it.first < CPDF_Parser::kMaxObjectNumber)
              cross_ref_table->AddCompressed(it.first, obj_num);
          }
        }
      }
    }
    numbers.clear();
  }
  // Resore default buffer size.
  syntax_->SetReadBufferSize(CPDF_ModuleMgr::kFileBufSize);
  return cross_ref_table;
}

std::unique_ptr<CPDF_CrossRefTable> CPDF_CrossRefParser::ParseCrossRefV5(
    FX_FILESIZE crossref_pos,
    CPDF_IndirectObjectHolder* holder) {
  syntax_->SetPos(crossref_pos);
  const auto stream = ToStream(
      syntax_->GetIndirectObject(holder, CPDF_SyntaxParser::ParseType::kLoose));
  if (!stream)
    return nullptr;

  const CPDF_Dictionary* trailer = stream->GetDict();
  DCHECK(trailer);
  const int32_t max_object_num = trailer->GetIntegerFor("Size");
  if (max_object_num < 0)
    return nullptr;

  auto result =
      pdfium::MakeUnique<CPDF_CrossRefTable>(ToDictionary(trailer->Clone()));

  std::vector<std::pair<int32_t, int32_t>> arrIndex;
  const CPDF_Array* pArray = trailer->GetArrayFor("Index");
  if (pArray) {
    for (size_t i = 0; i < pArray->GetCount() / 2; i++) {
      const CPDF_Object* pStartNumObj = pArray->GetObjectAt(i * 2);
      const CPDF_Object* pCountObj = pArray->GetObjectAt(i * 2 + 1);

      if (ToNumber(pStartNumObj) && ToNumber(pCountObj)) {
        int nStartNum = pStartNumObj->GetInteger();
        int nCount = pCountObj->GetInteger();
        if (nStartNum >= 0 && nCount > 0)
          arrIndex.push_back(std::make_pair(nStartNum, nCount));
      }
    }
  }

  if (arrIndex.empty())
    arrIndex.push_back(std::make_pair(0, max_object_num));

  pArray = trailer->GetArrayFor("W");
  if (!pArray)
    return nullptr;

  std::vector<uint32_t> WidthArray;
  FX_SAFE_UINT32 dwAccWidth = 0;
  for (size_t i = 0; i < pArray->GetCount(); ++i) {
    WidthArray.push_back(pArray->GetIntegerAt(i));
    dwAccWidth += WidthArray[i];
  }

  if (!dwAccWidth.IsValid() || WidthArray.size() < 3)
    return nullptr;

  uint32_t totalWidth = dwAccWidth.ValueOrDie();
  auto pAcc = pdfium::MakeRetain<CPDF_StreamAcc>(stream.get());
  pAcc->LoadAllDataFiltered();

  const uint8_t* pData = pAcc->GetData();
  uint32_t dwTotalSize = pAcc->GetSize();
  uint32_t segindex = 0;
  for (uint32_t i = 0; i < arrIndex.size(); i++) {
    int32_t startnum = arrIndex[i].first;
    if (startnum < 0)
      continue;

    uint32_t count = pdfium::base::checked_cast<uint32_t>(arrIndex[i].second);
    FX_SAFE_UINT32 dwCaculatedSize = segindex;
    dwCaculatedSize += count;
    dwCaculatedSize *= totalWidth;
    if (!dwCaculatedSize.IsValid() ||
        dwCaculatedSize.ValueOrDie() > dwTotalSize) {
      continue;
    }

    const uint8_t* segstart = pData + segindex * totalWidth;
    FX_SAFE_UINT32 dwMaxObjNum = startnum;
    dwMaxObjNum += count;
    if (!dwMaxObjNum.IsValid() || dwMaxObjNum.ValueOrDie() > max_object_num)
      continue;

    for (uint32_t j = 0; j < count; j++) {
      const uint32_t obj_num = startnum + j;
      CrossRefStreamObjType type = kNormal;
      const uint8_t* entrystart = segstart + j * totalWidth;
      if (WidthArray[0]) {
        type = static_cast<CrossRefStreamObjType>(
            GetVarInt(entrystart, WidthArray[0]));
      }

      switch (type) {
        case kFree:
          result->SetFree(obj_num);
          break;
        case kNormal: {
          const FX_FILESIZE offset =
              GetVarInt(entrystart + WidthArray[0], WidthArray[1]);
          result->AddNormal(obj_num, 0, offset);
        } break;
        case kCompressed: {
          const FX_FILESIZE entry_value =
              GetVarInt(entrystart + WidthArray[0], WidthArray[1]);
          const auto archive_obj_num = entry_value;
          if (archive_obj_num < 0 || archive_obj_num > max_object_num)
            return nullptr;

          result->AddCompressed(obj_num, archive_obj_num);
        } break;
        default:
          return nullptr;
      }
    }
    segindex += count;
  }
  return result;
}

CPDF_ReadValidator* CPDF_CrossRefParser::GetValidator() const {
  return syntax_->GetValidator().Get();
}
