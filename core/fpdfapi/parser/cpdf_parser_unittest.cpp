// Copyright 2015 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits>
#include <memory>
#include <string>
#include <vector>

#include "core/fpdfapi/parser/cpdf_cross_ref_parser.h"
#include "core/fpdfapi/parser/cpdf_linearized_header.h"
#include "core/fpdfapi/parser/cpdf_object.h"
#include "core/fpdfapi/parser/cpdf_parser.h"
#include "core/fpdfapi/parser/cpdf_syntax_parser.h"
#include "core/fxcrt/fx_extension.h"
#include "core/fxcrt/fx_stream.h"
#include "core/fxcrt/retain_ptr.h"
#include "testing/fx_string_testhelpers.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/utils/path_service.h"
#include "third_party/base/span.h"

namespace {

CPDF_CrossRefTable::ObjectInfo GetObjInfo(const CPDF_CrossRefTable* table,
                                          uint32_t obj_num) {
  const auto* info = table->GetObjectInfo(obj_num);
  return info ? *info : CPDF_CrossRefTable::ObjectInfo();
}

std::unique_ptr<CPDF_CrossRefTable> LoadCrossRefV4(
    const pdfium::span<const unsigned char>& data) {
  CPDF_SyntaxParser syntax;
  syntax.InitParser(pdfium::MakeRetain<CFX_BufferSeekableReadStream>(
                        data.data(), data.size()),
                    0);
  return CPDF_CrossRefParser(&syntax).ParseCrossRefV4(0, nullptr);
}

std::unique_ptr<CPDF_CrossRefTable> RebuildCrossRef(const char* file_path) {
  RetainPtr<IFX_SeekableReadStream> pFileAccess =
      IFX_SeekableReadStream::CreateFromFilename(file_path);
  if (!pFileAccess)
    return nullptr;

  CPDF_SyntaxParser syntax;
  syntax.InitParser(pFileAccess, 0);
  return CPDF_CrossRefParser(&syntax).RebuildCrossRef();
}

}  // namespace

// A wrapper class to help test member functions of CPDF_Parser.
class CPDF_TestParser : public CPDF_Parser {
 public:
  CPDF_TestParser() {}
  ~CPDF_TestParser() {}

  // Setup reading from a file and initial states.
  bool InitTestFromFile(const char* path) {
    RetainPtr<IFX_SeekableReadStream> pFileAccess =
        IFX_SeekableReadStream::CreateFromFilename(path);
    if (!pFileAccess)
      return false;

    // For the test file, the header is set at the beginning.
    m_pSyntax->InitParser(pFileAccess, 0);
    return true;
  }

  // Setup reading from a buffer and initial states.
  bool InitTestFromBufferWithOffset(const unsigned char* buffer,
                                    size_t len,
                                    int header_offset) {
    m_pSyntax->InitParser(
        pdfium::MakeRetain<CFX_BufferSeekableReadStream>(buffer, len),
        header_offset);
    return true;
  }

  bool InitTestFromBuffer(const unsigned char* buffer, size_t len) {
    return InitTestFromBufferWithOffset(buffer, len, 0 /*header_offset*/);
  }
};

TEST(cpdf_parser, RebuildCrossRefCorrectly) {
  CPDF_TestParser parser;
  std::string test_file;
  ASSERT_TRUE(PathService::GetTestFilePath("parser_rebuildxref_correct.pdf",
                                           &test_file));
  std::unique_ptr<CPDF_CrossRefTable> table =
      RebuildCrossRef(test_file.c_str());
  ASSERT_TRUE(table);
  ASSERT_TRUE(table->trailer());

  const FX_FILESIZE offsets[] = {0, 15, 61, 154, 296, 374, 450};
  const uint16_t versions[] = {0, 0, 2, 4, 6, 8, 0};
  for (size_t i = 0; i < FX_ArraySize(offsets); ++i)
    EXPECT_EQ(offsets[i], GetObjInfo(table.get(), i).pos);
  for (size_t i = 0; i < FX_ArraySize(versions); ++i)
    EXPECT_EQ(versions[i], GetObjInfo(table.get(), i).gennum);
}

TEST(cpdf_parser, RebuildCrossRefFailed) {
  CPDF_TestParser parser;
  std::string test_file;
  ASSERT_TRUE(PathService::GetTestFilePath(
      "parser_rebuildxref_error_notrailer.pdf", &test_file));
  std::unique_ptr<CPDF_CrossRefTable> table =
      RebuildCrossRef(test_file.c_str());
  ASSERT_TRUE(table);
  ASSERT_FALSE(table->trailer());
}

TEST(cpdf_parser, LoadCrossRefV4) {
  {
    const unsigned char xref_table[] =
        "xref \n"
        "0 6 \n"
        "0000000003 65535 f \n"
        "0000000017 00000 n \n"
        "0000000081 00000 n \n"
        "0000000000 00007 f \n"
        "0000000331 00000 n \n"
        "0000000409 00000 n \n"
        "trailer<<>>";  // Needed to end cross ref table reading.

    std::unique_ptr<CPDF_CrossRefTable> table = LoadCrossRefV4(xref_table);
    ASSERT_TRUE(table);
    const FX_FILESIZE offsets[] = {0, 17, 81, 0, 331, 409};
    const CPDF_CrossRefTable::ObjectType types[] = {
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kNotCompressed,
        CPDF_CrossRefTable::ObjectType::kNotCompressed,
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kNotCompressed,
        CPDF_CrossRefTable::ObjectType::kNotCompressed};
    for (size_t i = 0; i < FX_ArraySize(offsets); ++i) {
      EXPECT_EQ(offsets[i], GetObjInfo(table.get(), i).pos);
      EXPECT_EQ(types[i], GetObjInfo(table.get(), i).type);
    }
  }
  {
    const unsigned char xref_table[] =
        "xref \n"
        "0 1 \n"
        "0000000000 65535 f \n"
        "3 1 \n"
        "0000025325 00000 n \n"
        "8 2 \n"
        "0000025518 00002 n \n"
        "0000025635 00000 n \n"
        "12 1 \n"
        "0000025777 00000 n \n"
        "trailer<<>>";  // Needed to end cross ref table reading.

    std::unique_ptr<CPDF_CrossRefTable> table = LoadCrossRefV4(xref_table);
    ASSERT_TRUE(table);
    const FX_FILESIZE offsets[] = {0, 0,     0,     25325, 0, 0,    0,
                                   0, 25518, 25635, 0,     0, 25777};
    const CPDF_CrossRefTable::ObjectType types[] = {
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kNotCompressed,
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kNotCompressed,
        CPDF_CrossRefTable::ObjectType::kNotCompressed,
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kNotCompressed};
    for (size_t i = 0; i < FX_ArraySize(offsets); ++i) {
      EXPECT_EQ(offsets[i], GetObjInfo(table.get(), i).pos);
      EXPECT_EQ(types[i], GetObjInfo(table.get(), i).type);
    }
  }
  {
    const unsigned char xref_table[] =
        "xref \n"
        "0 1 \n"
        "0000000000 65535 f \n"
        "3 1 \n"
        "0000025325 00000 n \n"
        "8 2 \n"
        "0000000000 65535 f \n"
        "0000025635 00000 n \n"
        "12 1 \n"
        "0000025777 00000 n \n"
        "trailer<<>>";  // Needed to end cross ref table reading.
    std::unique_ptr<CPDF_CrossRefTable> table = LoadCrossRefV4(xref_table);
    ASSERT_TRUE(table);
    const FX_FILESIZE offsets[] = {0, 0, 0,     25325, 0, 0,    0,
                                   0, 0, 25635, 0,     0, 25777};
    const CPDF_CrossRefTable::ObjectType types[] = {
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kNotCompressed,
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kNotCompressed,
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kNotCompressed};
    for (size_t i = 0; i < FX_ArraySize(offsets); ++i) {
      EXPECT_EQ(offsets[i], GetObjInfo(table.get(), i).pos);
      EXPECT_EQ(types[i], GetObjInfo(table.get(), i).type);
    }
  }
  {
    const unsigned char xref_table[] =
        "xref \n"
        "0 7 \n"
        "0000000002 65535 f \n"
        "0000000023 00000 n \n"
        "0000000003 65535 f \n"
        "0000000004 65535 f \n"
        "0000000000 65535 f \n"
        "0000000045 00000 n \n"
        "0000000179 00000 n \n"
        "trailer<<>>";  // Needed to end cross ref table reading.

    std::unique_ptr<CPDF_CrossRefTable> table = LoadCrossRefV4(xref_table);
    ASSERT_TRUE(table);

    const FX_FILESIZE offsets[] = {0, 23, 0, 0, 0, 45, 179};
    const CPDF_CrossRefTable::ObjectType types[] = {
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kNotCompressed,
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kFree,
        CPDF_CrossRefTable::ObjectType::kNotCompressed,
        CPDF_CrossRefTable::ObjectType::kNotCompressed};
    for (size_t i = 0; i < FX_ArraySize(offsets); ++i) {
      EXPECT_EQ(offsets[i], GetObjInfo(table.get(), i).pos);
      EXPECT_EQ(types[i], GetObjInfo(table.get(), i).type);
    }
  }
}

TEST(cpdf_parser, ParseStartXRef) {
  CPDF_TestParser parser;
  std::string test_file;
  ASSERT_TRUE(
      PathService::GetTestFilePath("annotation_stamp_with_ap.pdf", &test_file));
  ASSERT_TRUE(parser.InitTestFromFile(test_file.c_str())) << test_file;

  EXPECT_EQ(100940, parser.ParseStartXRef());
  std::unique_ptr<CPDF_Object> cross_ref_v5_obj =
      parser.ParseIndirectObjectAt(100940, 0);
  ASSERT_TRUE(cross_ref_v5_obj);
  EXPECT_EQ(75u, cross_ref_v5_obj->GetObjNum());
}

TEST(cpdf_parser, ParseStartXRefWithHeaderOffset) {
  static constexpr FX_FILESIZE kTestHeaderOffset = 765;
  std::string test_file;
  ASSERT_TRUE(
      PathService::GetTestFilePath("annotation_stamp_with_ap.pdf", &test_file));
  RetainPtr<IFX_SeekableReadStream> pFileAccess =
      IFX_SeekableReadStream::CreateFromFilename(test_file.c_str());
  ASSERT_TRUE(pFileAccess);

  std::vector<unsigned char> data(pFileAccess->GetSize() + kTestHeaderOffset);
  ASSERT_TRUE(pFileAccess->ReadBlock(&data.front() + kTestHeaderOffset, 0,
                                     pFileAccess->GetSize()));
  CPDF_TestParser parser;
  parser.InitTestFromBufferWithOffset(&data.front(), data.size(),
                                      kTestHeaderOffset);

  EXPECT_EQ(100940, parser.ParseStartXRef());
  std::unique_ptr<CPDF_Object> cross_ref_v5_obj =
      parser.ParseIndirectObjectAt(100940, 0);
  ASSERT_TRUE(cross_ref_v5_obj);
  EXPECT_EQ(75u, cross_ref_v5_obj->GetObjNum());
}

TEST(cpdf_parser, ParseLinearizedWithHeaderOffset) {
  static constexpr FX_FILESIZE kTestHeaderOffset = 765;
  std::string test_file;
  ASSERT_TRUE(PathService::GetTestFilePath("linearized.pdf", &test_file));
  RetainPtr<IFX_SeekableReadStream> pFileAccess =
      IFX_SeekableReadStream::CreateFromFilename(test_file.c_str());
  ASSERT_TRUE(pFileAccess);

  std::vector<unsigned char> data(pFileAccess->GetSize() + kTestHeaderOffset);
  ASSERT_TRUE(pFileAccess->ReadBlock(&data.front() + kTestHeaderOffset, 0,
                                     pFileAccess->GetSize()));
  CPDF_TestParser parser;
  parser.InitTestFromBufferWithOffset(&data.front(), data.size(),
                                      kTestHeaderOffset);

  EXPECT_TRUE(parser.ParseLinearizedHeader());
}
