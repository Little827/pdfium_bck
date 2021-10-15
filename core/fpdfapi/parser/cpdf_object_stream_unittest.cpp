// Copyright 2021 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fpdfapi/parser/cpdf_object_stream.h"

#include <memory>
#include <utility>

#include "core/fpdfapi/parser/cpdf_dictionary.h"
#include "core/fpdfapi/parser/cpdf_name.h"
#include "core/fpdfapi/parser/cpdf_number.h"
#include "core/fpdfapi/parser/cpdf_stream.h"
#include "core/fpdfapi/parser/cpdf_string.h"
#include "core/fxcrt/fx_memory.h"
#include "core/fxcrt/fx_memory_wrappers.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/base/cxx17_backports.h"

using testing::ElementsAre;
using testing::Pair;

namespace {

const char kNormalStreamContent[] = "10 0 11 14 12 21<</Name /Foo>>[1 2 3]4";

}  // namespace

TEST(CPDF_ObjectStreamTest, StreamDictNormal) {
  auto dict = pdfium::MakeRetain<CPDF_Dictionary>();
  dict->SetNewFor<CPDF_Name>("Type", "ObjStm");
  dict->SetNewFor<CPDF_Number>("N", 3);
  dict->SetNewFor<CPDF_Number>("First", 17);

  size_t stream_data_len = pdfium::size(kNormalStreamContent);
  std::unique_ptr<uint8_t, FxFreeDeleter> stream_data(
      FX_AllocUninit(uint8_t, stream_data_len));
  memcpy(stream_data.get(), kNormalStreamContent, stream_data_len);

  auto stream = pdfium::MakeRetain<CPDF_Stream>(std::move(stream_data),
                                                stream_data_len, dict);
  auto obj_stream = CPDF_ObjectStream::Create(stream.Get());
  ASSERT_TRUE(obj_stream);

  EXPECT_THAT(obj_stream->objects_offsets(),
              ElementsAre(Pair(10, 0), Pair(11, 14), Pair(12, 21)));
}

TEST(CPDF_ObjectStreamTest, StreamNoDict) {
  size_t stream_data_len = pdfium::size(kNormalStreamContent);
  std::unique_ptr<uint8_t, FxFreeDeleter> stream_data(
      FX_AllocUninit(uint8_t, stream_data_len));
  memcpy(stream_data.get(), kNormalStreamContent, stream_data_len);

  auto stream = pdfium::MakeRetain<CPDF_Stream>(
      std::move(stream_data), stream_data_len, /*pDict=*/nullptr);
  EXPECT_FALSE(CPDF_ObjectStream::Create(stream.Get()));
}

TEST(CPDF_ObjectStreamTest, StreamDictNoType) {
  auto dict = pdfium::MakeRetain<CPDF_Dictionary>();
  dict->SetNewFor<CPDF_Number>("N", 3);
  dict->SetNewFor<CPDF_Number>("First", 5);

  size_t stream_data_len = pdfium::size(kNormalStreamContent);
  std::unique_ptr<uint8_t, FxFreeDeleter> stream_data(
      FX_AllocUninit(uint8_t, stream_data_len));
  memcpy(stream_data.get(), kNormalStreamContent, stream_data_len);

  auto stream = pdfium::MakeRetain<CPDF_Stream>(
      std::move(stream_data), stream_data_len, /*pDict=*/nullptr);
  EXPECT_FALSE(CPDF_ObjectStream::Create(stream.Get()));
}

TEST(CPDF_ObjectStreamTest, StreamDictWrongType) {
  auto dict = pdfium::MakeRetain<CPDF_Dictionary>();
  dict->SetNewFor<CPDF_String>("Type", "ObjStm", /*bHex=*/false);
  dict->SetNewFor<CPDF_Number>("N", 3);
  dict->SetNewFor<CPDF_Number>("First", 5);

  size_t stream_data_len = pdfium::size(kNormalStreamContent);
  std::unique_ptr<uint8_t, FxFreeDeleter> stream_data(
      FX_AllocUninit(uint8_t, stream_data_len));
  memcpy(stream_data.get(), kNormalStreamContent, stream_data_len);

  auto stream = pdfium::MakeRetain<CPDF_Stream>(
      std::move(stream_data), stream_data_len, /*pDict=*/nullptr);
  EXPECT_FALSE(CPDF_ObjectStream::Create(stream.Get()));
}

TEST(CPDF_ObjectStreamTest, StreamDictWrongTypeValue) {
  auto dict = pdfium::MakeRetain<CPDF_Dictionary>();
  dict->SetNewFor<CPDF_Name>("Type", "ObjStmmmm");
  dict->SetNewFor<CPDF_Number>("N", 3);
  dict->SetNewFor<CPDF_Number>("First", 5);

  size_t stream_data_len = pdfium::size(kNormalStreamContent);
  std::unique_ptr<uint8_t, FxFreeDeleter> stream_data(
      FX_AllocUninit(uint8_t, stream_data_len));
  memcpy(stream_data.get(), kNormalStreamContent, stream_data_len);

  auto stream = pdfium::MakeRetain<CPDF_Stream>(
      std::move(stream_data), stream_data_len, /*pDict=*/nullptr);
  EXPECT_FALSE(CPDF_ObjectStream::Create(stream.Get()));
}

TEST(CPDF_ObjectStreamTest, StreamDictNoCount) {
  auto dict = pdfium::MakeRetain<CPDF_Dictionary>();
  dict->SetNewFor<CPDF_Name>("Type", "ObjStm");
  dict->SetNewFor<CPDF_Number>("First", 5);

  size_t stream_data_len = pdfium::size(kNormalStreamContent);
  std::unique_ptr<uint8_t, FxFreeDeleter> stream_data(
      FX_AllocUninit(uint8_t, stream_data_len));
  memcpy(stream_data.get(), kNormalStreamContent, stream_data_len);

  auto stream = pdfium::MakeRetain<CPDF_Stream>(std::move(stream_data),
                                                stream_data_len, dict);
  EXPECT_FALSE(CPDF_ObjectStream::Create(stream.Get()));
}

TEST(CPDF_ObjectStreamTest, StreamDictFloatCount) {
  auto dict = pdfium::MakeRetain<CPDF_Dictionary>();
  dict->SetNewFor<CPDF_Name>("Type", "ObjStm");
  dict->SetNewFor<CPDF_Number>("N", 2.2f);
  dict->SetNewFor<CPDF_Number>("First", 5);

  size_t stream_data_len = pdfium::size(kNormalStreamContent);
  std::unique_ptr<uint8_t, FxFreeDeleter> stream_data(
      FX_AllocUninit(uint8_t, stream_data_len));
  memcpy(stream_data.get(), kNormalStreamContent, stream_data_len);

  auto stream = pdfium::MakeRetain<CPDF_Stream>(std::move(stream_data),
                                                stream_data_len, dict);
  EXPECT_FALSE(CPDF_ObjectStream::Create(stream.Get()));
}

TEST(CPDF_ObjectStreamTest, StreamDictNegativeCount) {
  auto dict = pdfium::MakeRetain<CPDF_Dictionary>();
  dict->SetNewFor<CPDF_Name>("Type", "ObjStm");
  dict->SetNewFor<CPDF_Number>("N", -1);
  dict->SetNewFor<CPDF_Number>("First", 5);

  size_t stream_data_len = pdfium::size(kNormalStreamContent);
  std::unique_ptr<uint8_t, FxFreeDeleter> stream_data(
      FX_AllocUninit(uint8_t, stream_data_len));
  memcpy(stream_data.get(), kNormalStreamContent, stream_data_len);

  auto stream = pdfium::MakeRetain<CPDF_Stream>(std::move(stream_data),
                                                stream_data_len, dict);
  EXPECT_FALSE(CPDF_ObjectStream::Create(stream.Get()));
}

TEST(CPDF_ObjectStreamTest, StreamDictCountTooBig) {
  auto dict = pdfium::MakeRetain<CPDF_Dictionary>();
  dict->SetNewFor<CPDF_Name>("Type", "ObjStm");
  dict->SetNewFor<CPDF_Number>("N", 999999999);
  dict->SetNewFor<CPDF_Number>("First", 5);

  size_t stream_data_len = pdfium::size(kNormalStreamContent);
  std::unique_ptr<uint8_t, FxFreeDeleter> stream_data(
      FX_AllocUninit(uint8_t, stream_data_len));
  memcpy(stream_data.get(), kNormalStreamContent, stream_data_len);

  auto stream = pdfium::MakeRetain<CPDF_Stream>(std::move(stream_data),
                                                stream_data_len, dict);
  EXPECT_FALSE(CPDF_ObjectStream::Create(stream.Get()));
}

TEST(CPDF_ObjectStreamTest, StreamDictNoOffset) {
  auto dict = pdfium::MakeRetain<CPDF_Dictionary>();
  dict->SetNewFor<CPDF_Name>("Type", "ObjStm");
  dict->SetNewFor<CPDF_Number>("N", 3);

  size_t stream_data_len = pdfium::size(kNormalStreamContent);
  std::unique_ptr<uint8_t, FxFreeDeleter> stream_data(
      FX_AllocUninit(uint8_t, stream_data_len));
  memcpy(stream_data.get(), kNormalStreamContent, stream_data_len);

  auto stream = pdfium::MakeRetain<CPDF_Stream>(std::move(stream_data),
                                                stream_data_len, dict);
  EXPECT_FALSE(CPDF_ObjectStream::Create(stream.Get()));
}

TEST(CPDF_ObjectStreamTest, StreamDictFloatOffset) {
  auto dict = pdfium::MakeRetain<CPDF_Dictionary>();
  dict->SetNewFor<CPDF_Name>("Type", "ObjStm");
  dict->SetNewFor<CPDF_Number>("N", 3);
  dict->SetNewFor<CPDF_Number>("First", 5.5f);

  size_t stream_data_len = pdfium::size(kNormalStreamContent);
  std::unique_ptr<uint8_t, FxFreeDeleter> stream_data(
      FX_AllocUninit(uint8_t, stream_data_len));
  memcpy(stream_data.get(), kNormalStreamContent, stream_data_len);

  auto stream = pdfium::MakeRetain<CPDF_Stream>(std::move(stream_data),
                                                stream_data_len, dict);
  EXPECT_FALSE(CPDF_ObjectStream::Create(stream.Get()));
}

TEST(CPDF_ObjectStreamTest, StreamDictNegativeOffset) {
  auto dict = pdfium::MakeRetain<CPDF_Dictionary>();
  dict->SetNewFor<CPDF_Name>("Type", "ObjStm");
  dict->SetNewFor<CPDF_Number>("N", 3);
  dict->SetNewFor<CPDF_Number>("First", -5);

  size_t stream_data_len = pdfium::size(kNormalStreamContent);
  std::unique_ptr<uint8_t, FxFreeDeleter> stream_data(
      FX_AllocUninit(uint8_t, stream_data_len));
  memcpy(stream_data.get(), kNormalStreamContent, stream_data_len);

  auto stream = pdfium::MakeRetain<CPDF_Stream>(std::move(stream_data),
                                                stream_data_len, dict);
  EXPECT_FALSE(CPDF_ObjectStream::Create(stream.Get()));
}

TEST(CPDF_ObjectStreamTest, StreamDictTooFewCount) {
  auto dict = pdfium::MakeRetain<CPDF_Dictionary>();
  dict->SetNewFor<CPDF_Name>("Type", "ObjStm");
  dict->SetNewFor<CPDF_Number>("N", 2);
  dict->SetNewFor<CPDF_Number>("First", 17);

  size_t stream_data_len = pdfium::size(kNormalStreamContent);
  std::unique_ptr<uint8_t, FxFreeDeleter> stream_data(
      FX_AllocUninit(uint8_t, stream_data_len));
  memcpy(stream_data.get(), kNormalStreamContent, stream_data_len);

  auto stream = pdfium::MakeRetain<CPDF_Stream>(std::move(stream_data),
                                                stream_data_len, dict);
  auto obj_stream = CPDF_ObjectStream::Create(stream.Get());
  ASSERT_TRUE(obj_stream);

  EXPECT_THAT(obj_stream->objects_offsets(),
              ElementsAre(Pair(10, 0), Pair(11, 14)));
}

TEST(CPDF_ObjectStreamTest, StreamDictTooManyObject) {
  auto dict = pdfium::MakeRetain<CPDF_Dictionary>();
  dict->SetNewFor<CPDF_Name>("Type", "ObjStm");
  dict->SetNewFor<CPDF_Number>("N", 9);
  dict->SetNewFor<CPDF_Number>("First", 17);

  size_t stream_data_len = pdfium::size(kNormalStreamContent);
  std::unique_ptr<uint8_t, FxFreeDeleter> stream_data(
      FX_AllocUninit(uint8_t, stream_data_len));
  memcpy(stream_data.get(), kNormalStreamContent, stream_data_len);

  auto stream = pdfium::MakeRetain<CPDF_Stream>(std::move(stream_data),
                                                stream_data_len, dict);
  auto obj_stream = CPDF_ObjectStream::Create(stream.Get());
  ASSERT_TRUE(obj_stream);

  // TODO(thestig): Can this avoid finding object 2?
  EXPECT_THAT(obj_stream->objects_offsets(),
              ElementsAre(Pair(2, 3), Pair(10, 0), Pair(11, 14), Pair(12, 21)));
}

TEST(CPDF_ObjectStreamTest, StreamDictGarbageObjNum) {
  auto dict = pdfium::MakeRetain<CPDF_Dictionary>();
  dict->SetNewFor<CPDF_Name>("Type", "ObjStm");
  dict->SetNewFor<CPDF_Number>("N", 3);
  dict->SetNewFor<CPDF_Number>("First", 19);

  const char kStreamContent[] = "10 0 hi 14 12 21<</Name /Foo>>[1 2 3]4";
  size_t stream_data_len = pdfium::size(kStreamContent);
  std::unique_ptr<uint8_t, FxFreeDeleter> stream_data(
      FX_AllocUninit(uint8_t, stream_data_len));
  memcpy(stream_data.get(), kStreamContent, stream_data_len);

  auto stream = pdfium::MakeRetain<CPDF_Stream>(std::move(stream_data),
                                                stream_data_len, dict);
  auto obj_stream = CPDF_ObjectStream::Create(stream.Get());
  ASSERT_TRUE(obj_stream);

  EXPECT_THAT(obj_stream->objects_offsets(),
              ElementsAre(Pair(10, 0), Pair(12, 21)));
}

TEST(CPDF_ObjectStreamTest, StreamDictGarbageOffset) {
  auto dict = pdfium::MakeRetain<CPDF_Dictionary>();
  dict->SetNewFor<CPDF_Name>("Type", "ObjStm");
  dict->SetNewFor<CPDF_Number>("N", 3);
  dict->SetNewFor<CPDF_Number>("First", 19);

  const char kStreamContent[] = "10 0 11 hi 12 21<</Name /Foo>>[1 2 3]4";
  size_t stream_data_len = pdfium::size(kStreamContent);
  std::unique_ptr<uint8_t, FxFreeDeleter> stream_data(
      FX_AllocUninit(uint8_t, stream_data_len));
  memcpy(stream_data.get(), kStreamContent, stream_data_len);

  auto stream = pdfium::MakeRetain<CPDF_Stream>(std::move(stream_data),
                                                stream_data_len, dict);
  auto obj_stream = CPDF_ObjectStream::Create(stream.Get());
  ASSERT_TRUE(obj_stream);

  EXPECT_THAT(obj_stream->objects_offsets(),
              ElementsAre(Pair(10, 0), Pair(11, 0), Pair(12, 21)));
}

TEST(CPDF_ObjectStreamTest, StreamDictDuplicateObjNum) {
  auto dict = pdfium::MakeRetain<CPDF_Dictionary>();
  dict->SetNewFor<CPDF_Name>("Type", "ObjStm");
  dict->SetNewFor<CPDF_Number>("N", 3);
  dict->SetNewFor<CPDF_Number>("First", 17);

  const char kStreamContent[] = "10 0 10 14 12 21<</Name /Foo>>[1 2 3]4";
  size_t stream_data_len = pdfium::size(kStreamContent);
  std::unique_ptr<uint8_t, FxFreeDeleter> stream_data(
      FX_AllocUninit(uint8_t, stream_data_len));
  memcpy(stream_data.get(), kStreamContent, stream_data_len);

  auto stream = pdfium::MakeRetain<CPDF_Stream>(std::move(stream_data),
                                                stream_data_len, dict);
  auto obj_stream = CPDF_ObjectStream::Create(stream.Get());
  ASSERT_TRUE(obj_stream);

  // TODO(thestg): Should object 10 be at offset 0 instead?
  EXPECT_THAT(obj_stream->objects_offsets(),
              ElementsAre(Pair(10, 14), Pair(12, 21)));
}
