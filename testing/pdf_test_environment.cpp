// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/pdf_test_environment.h"

#include "core/fxge/cfx_gemodule.h"

#if defined(OS_LINUX)
#include <libgen.h>
#include <unistd.h>
#endif

namespace {

#if defined(OS_LINUX) || defined(OS_CHROMEOS)
// This is duplicated from
// third_party/test_fonts/fontconfig/fontconfig_util_linux.cc to avoid adding
// a dependency on fontconfig.
std::string GetSysrootDir() {
  char buf[PATH_MAX + 1];
  auto count = readlink("/proc/self/exe", buf, PATH_MAX);
  assert(count > 0);
  buf[count] = '\0';
  return dirname(buf);
}
#endif

}  // namespace

PDFTestEnvironment::PDFTestEnvironment() = default;

PDFTestEnvironment::~PDFTestEnvironment() = default;

// testing::Environment:
void PDFTestEnvironment::SetUp() {
#if defined(OS_LINUX) || defined(OS_CHROMEOS)
  font_path_ = GetSysrootDir() + "/test_fonts";
  font_paths_[0] = font_path_.c_str();
  font_paths_[1] = nullptr;
  CFX_GEModule::Create(font_paths_);
#else
  CFX_GEModule::Create(nullptr);
#endif
}

void PDFTestEnvironment::TearDown() {
  CFX_GEModule::Destroy();
}
