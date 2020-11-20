// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fxjs/cfx_v8.h"

#include "core/fxcrt/fx_memory.h"
#include "fxjs/fxv8.h"
#include "third_party/base/allocator/partition_allocator/partition_alloc.h"

CFX_V8::CFX_V8(v8::Isolate* isolate) : m_pIsolate(isolate) {}

CFX_V8::~CFX_V8() = default;

v8::Local<v8::Value> CFX_V8::GetObjectProperty(
    v8::Local<v8::Object> pObj,
    ByteStringView bsUTF8PropertyName) {
  return fxv8::ReentrantGetObjectPropertyHelper(GetIsolate(), pObj,
                                                bsUTF8PropertyName);
}

std::vector<WideString> CFX_V8::GetObjectPropertyNames(
    v8::Local<v8::Object> pObj) {
  return fxv8::ReentrantGetObjectPropertyNamesHelper(GetIsolate(), pObj);
}

void CFX_V8::PutObjectProperty(v8::Local<v8::Object> pObj,
                               ByteStringView bsUTF8PropertyName,
                               v8::Local<v8::Value> pPut) {
  fxv8::ReentrantPutObjectPropertyHelper(GetIsolate(), pObj, bsUTF8PropertyName,
                                         pPut);
}

void CFX_V8::DisposeIsolate() {
  if (m_pIsolate)
    m_pIsolate.Release()->Dispose();
}


int CFX_V8::ToInt32(v8::Local<v8::Value> pValue) {
  return fxv8::ReentrantToInt32Helper(GetIsolate(), pValue);
}

bool CFX_V8::ToBoolean(v8::Local<v8::Value> pValue) {
  return fxv8::ReentrantToBooleanHelper(GetIsolate(), pValue);
}

double CFX_V8::ToDouble(v8::Local<v8::Value> pValue) {
  return fxv8::ReentrantToDoubleHelper(GetIsolate(), pValue);
}

WideString CFX_V8::ToWideString(v8::Local<v8::Value> pValue) {
  return fxv8::ReentrantToWideStringHelper(GetIsolate(), pValue);
}

ByteString CFX_V8::ToByteString(v8::Local<v8::Value> pValue) {
  return fxv8::ReentrantToByteStringHelper(GetIsolate(), pValue);
}

v8::Local<v8::Object> CFX_V8::ToObject(v8::Local<v8::Value> pValue) {
  return fxv8::ReentrantToObjectHelper(GetIsolate(), pValue);
}

v8::Local<v8::Array> CFX_V8::ToArray(v8::Local<v8::Value> pValue) {
  return fxv8::ReentrantToArrayHelper(GetIsolate(), pValue);
}

void* CFX_V8ArrayBufferAllocator::Allocate(size_t length) {
  if (length > kMaxAllowedBytes)
    return nullptr;
  return GetArrayBufferPartitionAllocator().root()->AllocFlags(
      pdfium::base::PartitionAllocZeroFill, length, "CFX_V8ArrayBuffer");
}

void* CFX_V8ArrayBufferAllocator::AllocateUninitialized(size_t length) {
  if (length > kMaxAllowedBytes)
    return nullptr;
  return GetArrayBufferPartitionAllocator().root()->Alloc(length,
                                                          "CFX_V8ArrayBuffer");
}

void CFX_V8ArrayBufferAllocator::Free(void* data, size_t length) {
  GetArrayBufferPartitionAllocator().root()->Free(data);
}
