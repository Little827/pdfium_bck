// Copyright 2021 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONSTANTS_ASCII_H_
#define CONSTANTS_ASCII_H_

namespace pdfium {
namespace ascii {

constexpr uint32_t kNul = 0x00;
constexpr uint32_t kControlA = 0x01;
constexpr uint32_t kControlB = 0x02;
constexpr uint32_t kControlC = 0x03;
constexpr uint32_t kBackspace = 0x08;
constexpr uint32_t kTab = 0x09;
constexpr uint32_t kNewline = 0x0a;
constexpr uint32_t kReturn = 0x0d;
constexpr uint32_t kControlV = 0x16;
constexpr uint32_t kControlX = 0x18;
constexpr uint32_t kControlZ = 0x1a;
constexpr uint32_t kEscape = 0x1b;
constexpr uint32_t kSpace = 0x20;

}  // namespace ascii
}  // namespace pdfium

#endif  // CONSTANTS_ASCII_H_
