// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include <utility>

#include "fxjs/cfx_keyvalue.h"

CFX_Value::CFX_Value() = default;

CFX_Value::CFX_Value(bool value) : nType(DataType::BOOLEAN), bData(value) {}

CFX_Value::CFX_Value(double value) : nType(DataType::NUMBER), dData(value) {}

CFX_Value::CFX_Value(ByteString value)
    : nType(DataType::STRING), sData(std::move(value)) {}

CFX_Value::CFX_Value(CFX_GlobalArray value)
    : nType(DataType::OBJECT), objData(std::move(value)) {}

CFX_Value::CFX_Value(CFX_Value&& that) = default;

CFX_Value::~CFX_Value() = default;

CFX_Value& CFX_Value::operator=(CFX_Value&& array) = default;

CFX_KeyValue::CFX_KeyValue() = default;

CFX_KeyValue::CFX_KeyValue(CFX_Value value) : CFX_Value(std::move(value)) {}

CFX_KeyValue::~CFX_KeyValue() = default;
