// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FPDFSDK_FPDF_EMBEDDERTEST_CONSTANTS_H_
#define FPDFSDK_FPDF_EMBEDDERTEST_CONSTANTS_H_

namespace fpdfsdk {

static constexpr char kBlankPage612By792MD5[] =
    "1940568c9ba33bac5d0b1ee9558c76b3";

#if defined(OS_MACOSX)
static constexpr char kHelloWorldOriginalMD5[] =
    "c38b75e16a13852aee3b97d77a0f0ee7";
#elif defined(OS_WIN)
static constexpr char kHelloWorldOriginalMD5[] =
    "795b7ce1626931aa06af0fa23b7d80bb";
#else
static constexpr char kHelloWorldOriginalMD5[] =
    "2baa4c0e1758deba1b9c908e1fbd04ed";
#endif

#if defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_)
static constexpr char kBug890322MD5[] = "793689536cf64fe792c2f241888c0cf3";
static constexpr char kManyRectanglesOriginalMD5[] =
    "4e7e280c1597222afcb0ee3bb90ec119";
static constexpr char kRectanglesOriginalMD5[] =
    "b4e411a6b5ffa59a50efede2efece597";
static constexpr char kRectanglesShrunkMD5[] =
    "78c52d6029283090036e6db6683401e2";
#else
static constexpr char kBug890322MD5[] = "6c674642154408e877d88c6c082d67e9";
static constexpr char kManyRectanglesOriginalMD5[] =
    "b0170c575b65ecb93ebafada0ff0f038";
static constexpr char kRectanglesOriginalMD5[] =
    "0a90de37f52127619c3dfb642b5fa2fe";
static constexpr char kRectanglesShrunkMD5[] =
    "f4136cc9209207ab60eb8381a3df2e69";
#endif

}  // namespace fpdfsdk

#endif  // FPDFSDK_FPDF_EMBEDDERTEST_CONSTANTS_H_
