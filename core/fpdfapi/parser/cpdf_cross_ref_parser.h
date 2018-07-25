// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FPDFAPI_PARSER_CPDF_CROSS_REF_PARSER_H_
#define CORE_FPDFAPI_PARSER_CPDF_CROSS_REF_PARSER_H_

#include <memory>

#include "core/fxcrt/fx_system.h"
#include "core/fxcrt/unowned_ptr.h"

class CPDF_CrossRefTable;
class CPDF_ReadValidator;
class CPDF_SyntaxParser;
class CPDF_IndirectObjectHolder;

class CPDF_CrossRefParser {
 public:
  explicit CPDF_CrossRefParser(CPDF_SyntaxParser* syntax);
  ~CPDF_CrossRefParser();

  std::unique_ptr<CPDF_CrossRefTable> RebuildCrossRef();
  std::unique_ptr<CPDF_CrossRefTable> ParseCrossRefV5(
      FX_FILESIZE crossref_pos,
      CPDF_IndirectObjectHolder* holder);
  std::unique_ptr<CPDF_CrossRefTable> ParseCrossRefV4(
      FX_FILESIZE crossref_pos,
      CPDF_IndirectObjectHolder* holder);
  std::unique_ptr<CPDF_CrossRefTable> ParseCrossRef(
      FX_FILESIZE crossref_pos,
      CPDF_IndirectObjectHolder* holder);

 private:
  std::unique_ptr<CPDF_CrossRefTable> ParseCrossRefV4Internal(
      FX_FILESIZE crossref_pos,
      CPDF_IndirectObjectHolder* holder);
  std::unique_ptr<CPDF_CrossRefTable> ParseAndAppendCrossRefSubsectionData(
      uint32_t start_objnum,
      uint32_t count);

  CPDF_ReadValidator* GetValidator() const;

  UnownedPtr<CPDF_SyntaxParser> syntax_;
};

#endif  // CORE_FPDFAPI_PARSER_CPDF_CROSS_REF_PARSER_H_
