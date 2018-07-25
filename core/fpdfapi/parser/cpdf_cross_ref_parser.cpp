// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fpdfapi/parser/cpdf_cross_ref_parser.h"

#include <utility>
#include <vector>

#include "core/fpdfapi/parser/cpdf_cross_ref_table.h"
#include "core/fpdfapi/parser/cpdf_dictionary.h"
#include "core/fpdfapi/parser/cpdf_object_stream.h"
#include "core/fpdfapi/parser/cpdf_parser.h"
#include "core/fpdfapi/parser/cpdf_read_validator.h"
#include "core/fpdfapi/parser/cpdf_stream.h"
#include "core/fpdfapi/parser/cpdf_syntax_parser.h"

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

CPDF_ReadValidator* CPDF_CrossRefParser::GetValidator() const {
  return syntax_->GetValidator().Get();
}
