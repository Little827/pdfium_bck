// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "fxjs/cfx_v8.h"

#include <memory>

#include "testing/gtest/include/gtest/gtest.h"
#include "testing/test_support.h"
#include "third_party/base/ptr_util.h"

namespace {

struct V8IsolateDeleter {
  inline void operator()(v8::Isolate* ptr) const { ptr->Dispose(); }
};

}  // namespace

class FXV8UnitTest : public ::testing::Test {
 public:
  FXV8UnitTest()
      : m_pArrayBufferAllocator(
            pdfium::MakeUnique<CFX_V8ArrayBufferAllocator>()) {
    v8::Isolate::CreateParams params;
    params.array_buffer_allocator = m_pArrayBufferAllocator.get();
    m_pIsolate.reset(v8::Isolate::New(params));
    m_pV8 = pdfium::MakeUnique<CFX_V8>(m_pIsolate.get());
  }
  ~FXV8UnitTest() override = default;

  v8::Isolate* isolate() const { return m_pIsolate.get(); }
  CFX_V8* GetV8() const { return m_pV8.get(); }

 protected:
  std::unique_ptr<CFX_V8ArrayBufferAllocator> m_pArrayBufferAllocator;
  std::unique_ptr<v8::Isolate, V8IsolateDeleter> m_pIsolate;
  std::unique_ptr<CFX_V8> m_pV8;
};

TEST_F(FXV8UnitTest, EmptyLocal) {
  v8::Isolate::Scope isolate_scope(isolate());
  v8::HandleScope handle_scope(isolate());
  v8::Context::Scope context_scope(v8::Context::New(isolate()));

  v8::Local<v8::Value> empty;
  EXPECT_FALSE(GetV8()->ToBoolean(empty));
  EXPECT_EQ(0, GetV8()->ToInt32(empty));
  EXPECT_EQ(0.0, GetV8()->ToDouble(empty));
  EXPECT_EQ(L"", GetV8()->ToWideString(empty));
  EXPECT_TRUE(GetV8()->ToObject(empty).IsEmpty());
  EXPECT_TRUE(GetV8()->ToArray(empty).IsEmpty());
}

TEST_F(FXV8UnitTest, NewNull) {
  v8::Isolate::Scope isolate_scope(isolate());
  v8::HandleScope handle_scope(isolate());
  v8::Context::Scope context_scope(v8::Context::New(isolate()));

  auto nullz = GetV8()->NewNull();
  EXPECT_FALSE(GetV8()->ToBoolean(nullz));
  EXPECT_EQ(0, GetV8()->ToInt32(nullz));
  EXPECT_EQ(0.0, GetV8()->ToDouble(nullz));
  EXPECT_EQ(L"null", GetV8()->ToWideString(nullz));
  EXPECT_TRUE(GetV8()->ToObject(nullz).IsEmpty());
  EXPECT_TRUE(GetV8()->ToArray(nullz).IsEmpty());
}

TEST_F(FXV8UnitTest, NewUndefined) {
  v8::Isolate::Scope isolate_scope(isolate());
  v8::HandleScope handle_scope(isolate());
  v8::Context::Scope context_scope(v8::Context::New(isolate()));

  auto undef = GetV8()->NewUndefined();
  EXPECT_FALSE(GetV8()->ToBoolean(undef));
  EXPECT_EQ(0, GetV8()->ToInt32(undef));
  EXPECT_TRUE(std::isnan(GetV8()->ToDouble(undef)));
  EXPECT_EQ(L"undefined", GetV8()->ToWideString(undef));
  EXPECT_TRUE(GetV8()->ToObject(undef).IsEmpty());
  EXPECT_TRUE(GetV8()->ToArray(undef).IsEmpty());
}

TEST_F(FXV8UnitTest, NewBoolean) {
  v8::Isolate::Scope isolate_scope(isolate());
  v8::HandleScope handle_scope(isolate());
  v8::Context::Scope context_scope(v8::Context::New(isolate()));

  auto boolz = GetV8()->NewBoolean(true);
  EXPECT_TRUE(GetV8()->ToBoolean(boolz));
  EXPECT_EQ(1, GetV8()->ToInt32(boolz));
  EXPECT_EQ(1.0, GetV8()->ToDouble(boolz));
  EXPECT_EQ(L"true", GetV8()->ToWideString(boolz));
  EXPECT_TRUE(GetV8()->ToObject(boolz).IsEmpty());
  EXPECT_TRUE(GetV8()->ToArray(boolz).IsEmpty());
}

TEST_F(FXV8UnitTest, NewNumber) {
  v8::Isolate::Scope isolate_scope(isolate());
  v8::HandleScope handle_scope(isolate());
  v8::Context::Scope context_scope(v8::Context::New(isolate()));

  auto num = GetV8()->NewNumber(42.1);
  EXPECT_TRUE(GetV8()->ToBoolean(num));
  EXPECT_EQ(42, GetV8()->ToInt32(num));
  EXPECT_EQ(42.1, GetV8()->ToDouble(num));
  EXPECT_EQ(L"42.1", GetV8()->ToWideString(num));
  EXPECT_TRUE(GetV8()->ToObject(num).IsEmpty());
  EXPECT_TRUE(GetV8()->ToArray(num).IsEmpty());
}

TEST_F(FXV8UnitTest, NewString) {
  v8::Isolate::Scope isolate_scope(isolate());
  v8::HandleScope handle_scope(isolate());
  v8::Context::Scope context_scope(v8::Context::New(isolate()));

  auto str = GetV8()->NewString(L"123");
  EXPECT_TRUE(GetV8()->ToBoolean(str));
  EXPECT_EQ(123, GetV8()->ToInt32(str));
  EXPECT_EQ(123, GetV8()->ToDouble(str));
  EXPECT_EQ(L"123", GetV8()->ToWideString(str));
  EXPECT_TRUE(GetV8()->ToObject(str).IsEmpty());
  EXPECT_TRUE(GetV8()->ToArray(str).IsEmpty());
}

TEST_F(FXV8UnitTest, NewDate) {
  v8::Isolate::Scope isolate_scope(isolate());
  v8::HandleScope handle_scope(isolate());
  v8::Context::Scope context_scope(v8::Context::New(isolate()));

  auto date = GetV8()->NewDate(1111111111);
  EXPECT_TRUE(GetV8()->ToBoolean(date));
  EXPECT_EQ(1111111111, GetV8()->ToInt32(date));
  EXPECT_EQ(1111111111.0, GetV8()->ToDouble(date));
  EXPECT_NE(L"", GetV8()->ToWideString(date));  // exact format varies.
  EXPECT_TRUE(GetV8()->ToObject(date)->IsObject());
  EXPECT_TRUE(GetV8()->ToArray(date).IsEmpty());
}

TEST_F(FXV8UnitTest, NewArray) {
  v8::Isolate::Scope isolate_scope(isolate());
  v8::HandleScope handle_scope(isolate());
  v8::Context::Scope context_scope(v8::Context::New(isolate()));

  auto array = GetV8()->NewArray();
  EXPECT_EQ(0u, GetV8()->GetArrayLength(array));
  EXPECT_FALSE(GetV8()->GetArrayElement(array, 2).IsEmpty());
  EXPECT_TRUE(GetV8()->GetArrayElement(array, 2)->IsUndefined());
  EXPECT_EQ(0u, GetV8()->GetArrayLength(array));

  GetV8()->PutArrayElement(array, 3, GetV8()->NewNumber(12));
  EXPECT_FALSE(GetV8()->GetArrayElement(array, 2).IsEmpty());
  EXPECT_TRUE(GetV8()->GetArrayElement(array, 2)->IsUndefined());
  EXPECT_FALSE(GetV8()->GetArrayElement(array, 3).IsEmpty());
  EXPECT_TRUE(GetV8()->GetArrayElement(array, 3)->IsNumber());
  EXPECT_EQ(4u, GetV8()->GetArrayLength(array));

  EXPECT_TRUE(GetV8()->ToBoolean(array));
  EXPECT_EQ(0, GetV8()->ToInt32(array));
  double d = GetV8()->ToDouble(array);
  EXPECT_NE(d, d);  // i.e. NaN.
  EXPECT_EQ(L",,,12", GetV8()->ToWideString(array));
  EXPECT_TRUE(GetV8()->ToObject(array)->IsObject());
  EXPECT_TRUE(GetV8()->ToArray(array)->IsArray());
}

TEST_F(FXV8UnitTest, NewObject) {
  v8::Isolate::Scope isolate_scope(isolate());
  v8::HandleScope handle_scope(isolate());
  v8::Context::Scope context_scope(v8::Context::New(isolate()));

  auto object = GetV8()->NewObject();
  ASSERT_FALSE(object.IsEmpty());
  EXPECT_EQ(0u, GetV8()->GetObjectPropertyNames(object).size());
  EXPECT_FALSE(GetV8()->GetObjectProperty(object, L"clams").IsEmpty());
  EXPECT_TRUE(GetV8()->GetObjectProperty(object, L"clams")->IsUndefined());
  EXPECT_EQ(0u, GetV8()->GetObjectPropertyNames(object).size());

  GetV8()->PutObjectProperty(object, L"clams", GetV8()->NewNumber(12));
  EXPECT_FALSE(GetV8()->GetObjectProperty(object, L"clams").IsEmpty());
  EXPECT_TRUE(GetV8()->GetObjectProperty(object, L"clams")->IsNumber());
  EXPECT_EQ(1u, GetV8()->GetObjectPropertyNames(object).size());
  EXPECT_EQ(L"clams", GetV8()->GetObjectPropertyNames(object)[0]);

  EXPECT_TRUE(GetV8()->ToBoolean(object));
  EXPECT_EQ(0, GetV8()->ToInt32(object));
  double d = GetV8()->ToDouble(object);
  EXPECT_NE(d, d);  // i.e. NaN.
  EXPECT_EQ(L"[object Object]", GetV8()->ToWideString(object));
  EXPECT_TRUE(GetV8()->ToObject(object)->IsObject());
  EXPECT_TRUE(GetV8()->ToArray(object).IsEmpty());
}
