// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "fxjs/cfx_v8_isolate_wrapper.h"

#include <math.h>

#include <memory>

#include "testing/fxv8_unittest.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "v8/include/v8-container.h"
#include "v8/include/v8-context.h"
#include "v8/include/v8-date.h"
#include "v8/include/v8-isolate.h"

namespace {
bool getter_sentinel = false;
bool setter_sentinel = false;
}  // namespace

class CFXV8IsolateWrapperUnitTest : public FXV8UnitTest {
 public:
  CFXV8IsolateWrapperUnitTest() = default;
  ~CFXV8IsolateWrapperUnitTest() override = default;

  // FXV8UnitTest:
  void SetUp() override {
    FXV8UnitTest::SetUp();
    cfx_v8_ = std::make_unique<CFX_V8IsolateWrapper>(isolate());
  }

  CFX_V8IsolateWrapper* isolate_wrapper() const { return cfx_v8_.get(); }

 protected:
  std::unique_ptr<CFX_V8IsolateWrapper> cfx_v8_;
};

TEST_F(CFXV8IsolateWrapperUnitTest, EmptyLocal) {
  v8::Isolate::Scope isolate_scope(isolate());
  v8::HandleScope handle_scope(isolate());
  v8::Context::Scope context_scope(v8::Context::New(isolate()));

  v8::Local<v8::Value> empty;
  EXPECT_FALSE(isolate_wrapper()->ToBoolean(empty));
  EXPECT_EQ(0, isolate_wrapper()->ToInt32(empty));
  EXPECT_EQ(0.0, isolate_wrapper()->ToDouble(empty));
  EXPECT_EQ("", isolate_wrapper()->ToByteString(empty));
  EXPECT_EQ(L"", isolate_wrapper()->ToWideString(empty));
  EXPECT_TRUE(isolate_wrapper()->ToObject(empty).IsEmpty());
  EXPECT_TRUE(isolate_wrapper()->ToArray(empty).IsEmpty());

  // Can't set properties on empty objects, but does not fault.
  v8::Local<v8::Value> marker = isolate_wrapper()->NewNumber(2);
  v8::Local<v8::Object> empty_object;
  isolate_wrapper()->PutObjectProperty(empty_object, "clams", marker);
  EXPECT_TRUE(
      isolate_wrapper()->GetObjectProperty(empty_object, "clams").IsEmpty());
  EXPECT_EQ(0u, isolate_wrapper()->GetObjectPropertyNames(empty_object).size());

  // Can't set elements in empty arrays, but does not fault.
  v8::Local<v8::Array> empty_array;
  isolate_wrapper()->PutArrayElement(empty_array, 0, marker);
  EXPECT_TRUE(isolate_wrapper()->GetArrayElement(empty_array, 0).IsEmpty());
  EXPECT_EQ(0u, isolate_wrapper()->GetArrayLength(empty_array));
}

TEST_F(CFXV8IsolateWrapperUnitTest, NewNull) {
  v8::Isolate::Scope isolate_scope(isolate());
  v8::HandleScope handle_scope(isolate());
  v8::Context::Scope context_scope(v8::Context::New(isolate()));

  auto nullz = isolate_wrapper()->NewNull();
  EXPECT_FALSE(isolate_wrapper()->ToBoolean(nullz));
  EXPECT_EQ(0, isolate_wrapper()->ToInt32(nullz));
  EXPECT_EQ(0.0, isolate_wrapper()->ToDouble(nullz));
  EXPECT_EQ("null", isolate_wrapper()->ToByteString(nullz));
  EXPECT_EQ(L"null", isolate_wrapper()->ToWideString(nullz));
  EXPECT_TRUE(isolate_wrapper()->ToObject(nullz).IsEmpty());
  EXPECT_TRUE(isolate_wrapper()->ToArray(nullz).IsEmpty());
}

TEST_F(CFXV8IsolateWrapperUnitTest, NewUndefined) {
  v8::Isolate::Scope isolate_scope(isolate());
  v8::HandleScope handle_scope(isolate());
  v8::Context::Scope context_scope(v8::Context::New(isolate()));

  auto undef = isolate_wrapper()->NewUndefined();
  EXPECT_FALSE(isolate_wrapper()->ToBoolean(undef));
  EXPECT_EQ(0, isolate_wrapper()->ToInt32(undef));
  EXPECT_TRUE(isnan(isolate_wrapper()->ToDouble(undef)));
  EXPECT_EQ("undefined", isolate_wrapper()->ToByteString(undef));
  EXPECT_EQ(L"undefined", isolate_wrapper()->ToWideString(undef));
  EXPECT_TRUE(isolate_wrapper()->ToObject(undef).IsEmpty());
  EXPECT_TRUE(isolate_wrapper()->ToArray(undef).IsEmpty());
}

TEST_F(CFXV8IsolateWrapperUnitTest, NewBoolean) {
  v8::Isolate::Scope isolate_scope(isolate());
  v8::HandleScope handle_scope(isolate());
  v8::Context::Scope context_scope(v8::Context::New(isolate()));

  auto boolz = isolate_wrapper()->NewBoolean(true);
  EXPECT_TRUE(isolate_wrapper()->ToBoolean(boolz));
  EXPECT_EQ(1, isolate_wrapper()->ToInt32(boolz));
  EXPECT_EQ(1.0, isolate_wrapper()->ToDouble(boolz));
  EXPECT_EQ("true", isolate_wrapper()->ToByteString(boolz));
  EXPECT_EQ(L"true", isolate_wrapper()->ToWideString(boolz));
  EXPECT_TRUE(isolate_wrapper()->ToObject(boolz).IsEmpty());
  EXPECT_TRUE(isolate_wrapper()->ToArray(boolz).IsEmpty());

  boolz = isolate_wrapper()->NewBoolean(false);
  EXPECT_FALSE(isolate_wrapper()->ToBoolean(boolz));
  EXPECT_EQ(0, isolate_wrapper()->ToInt32(boolz));
  EXPECT_EQ(0.0, isolate_wrapper()->ToDouble(boolz));
  EXPECT_EQ("false", isolate_wrapper()->ToByteString(boolz));
  EXPECT_EQ(L"false", isolate_wrapper()->ToWideString(boolz));
  EXPECT_TRUE(isolate_wrapper()->ToObject(boolz).IsEmpty());
  EXPECT_TRUE(isolate_wrapper()->ToArray(boolz).IsEmpty());
}

TEST_F(CFXV8IsolateWrapperUnitTest, NewNumber) {
  v8::Isolate::Scope isolate_scope(isolate());
  v8::HandleScope handle_scope(isolate());
  v8::Context::Scope context_scope(v8::Context::New(isolate()));

  auto num = isolate_wrapper()->NewNumber(42.1);
  EXPECT_TRUE(isolate_wrapper()->ToBoolean(num));
  EXPECT_EQ(42, isolate_wrapper()->ToInt32(num));
  EXPECT_EQ(42.1, isolate_wrapper()->ToDouble(num));
  EXPECT_EQ("42.1", isolate_wrapper()->ToByteString(num));
  EXPECT_EQ(L"42.1", isolate_wrapper()->ToWideString(num));
  EXPECT_TRUE(isolate_wrapper()->ToObject(num).IsEmpty());
  EXPECT_TRUE(isolate_wrapper()->ToArray(num).IsEmpty());
}

TEST_F(CFXV8IsolateWrapperUnitTest, NewString) {
  v8::Isolate::Scope isolate_scope(isolate());
  v8::HandleScope handle_scope(isolate());
  v8::Context::Scope context_scope(v8::Context::New(isolate()));

  auto str = isolate_wrapper()->NewString("123");
  EXPECT_TRUE(isolate_wrapper()->ToBoolean(str));
  EXPECT_EQ(123, isolate_wrapper()->ToInt32(str));
  EXPECT_EQ(123, isolate_wrapper()->ToDouble(str));
  EXPECT_EQ("123", isolate_wrapper()->ToByteString(str));
  EXPECT_EQ(L"123", isolate_wrapper()->ToWideString(str));
  EXPECT_TRUE(isolate_wrapper()->ToObject(str).IsEmpty());
  EXPECT_TRUE(isolate_wrapper()->ToArray(str).IsEmpty());

  auto str2 = isolate_wrapper()->NewString(L"123");
  EXPECT_TRUE(isolate_wrapper()->ToBoolean(str2));
  EXPECT_EQ(123, isolate_wrapper()->ToInt32(str2));
  EXPECT_EQ(123, isolate_wrapper()->ToDouble(str2));
  EXPECT_EQ("123", isolate_wrapper()->ToByteString(str2));
  EXPECT_EQ(L"123", isolate_wrapper()->ToWideString(str2));
  EXPECT_TRUE(isolate_wrapper()->ToObject(str2).IsEmpty());
  EXPECT_TRUE(isolate_wrapper()->ToArray(str2).IsEmpty());
}

TEST_F(CFXV8IsolateWrapperUnitTest, NewDate) {
  v8::Isolate::Scope isolate_scope(isolate());
  v8::HandleScope handle_scope(isolate());
  v8::Context::Scope context_scope(v8::Context::New(isolate()));

  auto date = isolate_wrapper()->NewDate(1111111111);
  EXPECT_TRUE(isolate_wrapper()->ToBoolean(date));
  EXPECT_EQ(1111111111, isolate_wrapper()->ToInt32(date));
  EXPECT_EQ(1111111111.0, isolate_wrapper()->ToDouble(date));
  EXPECT_NE("", isolate_wrapper()->ToByteString(date));  // exact format varies.
  EXPECT_NE(L"",
            isolate_wrapper()->ToWideString(date));  // exact format varies.
  EXPECT_TRUE(isolate_wrapper()->ToObject(date)->IsObject());
  EXPECT_TRUE(isolate_wrapper()->ToArray(date).IsEmpty());
}

TEST_F(CFXV8IsolateWrapperUnitTest, NewArray) {
  v8::Isolate::Scope isolate_scope(isolate());
  v8::HandleScope handle_scope(isolate());
  v8::Context::Scope context_scope(v8::Context::New(isolate()));

  auto array = isolate_wrapper()->NewArray();
  EXPECT_EQ(0u, isolate_wrapper()->GetArrayLength(array));
  EXPECT_FALSE(isolate_wrapper()->GetArrayElement(array, 2).IsEmpty());
  EXPECT_TRUE(isolate_wrapper()->GetArrayElement(array, 2)->IsUndefined());
  EXPECT_EQ(0u, isolate_wrapper()->GetArrayLength(array));

  isolate_wrapper()->PutArrayElement(array, 3,
                                     isolate_wrapper()->NewNumber(12));
  EXPECT_FALSE(isolate_wrapper()->GetArrayElement(array, 2).IsEmpty());
  EXPECT_TRUE(isolate_wrapper()->GetArrayElement(array, 2)->IsUndefined());
  EXPECT_FALSE(isolate_wrapper()->GetArrayElement(array, 3).IsEmpty());
  EXPECT_TRUE(isolate_wrapper()->GetArrayElement(array, 3)->IsNumber());
  EXPECT_EQ(4u, isolate_wrapper()->GetArrayLength(array));

  EXPECT_TRUE(isolate_wrapper()->ToBoolean(array));
  EXPECT_EQ(0, isolate_wrapper()->ToInt32(array));
  double d = isolate_wrapper()->ToDouble(array);
  EXPECT_NE(d, d);  // i.e. NaN.
  EXPECT_EQ(L",,,12", isolate_wrapper()->ToWideString(array));
  EXPECT_TRUE(isolate_wrapper()->ToObject(array)->IsObject());
  EXPECT_TRUE(isolate_wrapper()->ToArray(array)->IsArray());
}

TEST_F(CFXV8IsolateWrapperUnitTest, NewObject) {
  v8::Isolate::Scope isolate_scope(isolate());
  v8::HandleScope handle_scope(isolate());
  v8::Context::Scope context_scope(v8::Context::New(isolate()));

  auto object = isolate_wrapper()->NewObject();
  ASSERT_FALSE(object.IsEmpty());
  EXPECT_EQ(0u, isolate_wrapper()->GetObjectPropertyNames(object).size());
  EXPECT_FALSE(isolate_wrapper()->GetObjectProperty(object, "clams").IsEmpty());
  EXPECT_TRUE(
      isolate_wrapper()->GetObjectProperty(object, "clams")->IsUndefined());
  EXPECT_EQ(0u, isolate_wrapper()->GetObjectPropertyNames(object).size());

  isolate_wrapper()->PutObjectProperty(object, "clams",
                                       isolate_wrapper()->NewNumber(12));
  EXPECT_FALSE(isolate_wrapper()->GetObjectProperty(object, "clams").IsEmpty());
  EXPECT_TRUE(
      isolate_wrapper()->GetObjectProperty(object, "clams")->IsNumber());
  EXPECT_EQ(1u, isolate_wrapper()->GetObjectPropertyNames(object).size());
  EXPECT_EQ(L"clams", isolate_wrapper()->GetObjectPropertyNames(object)[0]);

  EXPECT_TRUE(isolate_wrapper()->ToBoolean(object));
  EXPECT_EQ(0, isolate_wrapper()->ToInt32(object));
  double d = isolate_wrapper()->ToDouble(object);
  EXPECT_NE(d, d);  // i.e. NaN.
  EXPECT_EQ(L"[object Object]", isolate_wrapper()->ToWideString(object));
  EXPECT_TRUE(isolate_wrapper()->ToObject(object)->IsObject());
  EXPECT_TRUE(isolate_wrapper()->ToArray(object).IsEmpty());
}

TEST_F(CFXV8IsolateWrapperUnitTest, ThrowFromGetter) {
  v8::Isolate::Scope isolate_scope(isolate());
  v8::HandleScope handle_scope(isolate());
  v8::Local<v8::Context> context = v8::Context::New(isolate());
  v8::Context::Scope context_scope(context);

  v8::Local<v8::Object> object = isolate_wrapper()->NewObject();
  v8::Local<v8::String> name = isolate_wrapper()->NewString("clams");
  EXPECT_TRUE(
      object
          ->SetAccessor(context, name,
                        [](v8::Local<v8::Name> property,
                           const v8::PropertyCallbackInfo<v8::Value>& info) {
                          getter_sentinel = true;
                          info.GetIsolate()->ThrowException(property);
                        })
          .FromJust());
  getter_sentinel = false;
  EXPECT_TRUE(isolate_wrapper()->GetObjectProperty(object, "clams").IsEmpty());
  EXPECT_TRUE(getter_sentinel);
}

TEST_F(CFXV8IsolateWrapperUnitTest, ThrowFromSetter) {
  v8::Isolate::Scope isolate_scope(isolate());
  v8::HandleScope handle_scope(isolate());
  v8::Local<v8::Context> context = v8::Context::New(isolate());
  v8::Context::Scope context_scope(context);

  v8::Local<v8::Object> object = isolate_wrapper()->NewObject();
  v8::Local<v8::String> name = isolate_wrapper()->NewString("clams");
  EXPECT_TRUE(object
                  ->SetAccessor(context, name, nullptr,
                                [](v8::Local<v8::Name> property,
                                   v8::Local<v8::Value> value,
                                   const v8::PropertyCallbackInfo<void>& info) {
                                  setter_sentinel = true;
                                  info.GetIsolate()->ThrowException(property);
                                })
                  .FromJust());
  setter_sentinel = false;
  isolate_wrapper()->PutObjectProperty(object, "clams", name);
  EXPECT_TRUE(setter_sentinel);
}
