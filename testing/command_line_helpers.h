// Copyright 2022 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TESTING_COMMAND_LINE_HELPERS_H_
#define TESTING_COMMAND_LINE_HELPERS_H_

#include <string>

// `arg` is expected to be "--key=value", and `key` is "--key=".
bool ParseSwitchKeyValue(const std::string& arg,
                         const std::string& key,
                         std::string* value);

#endif  // TESTING_COMMAND_LINE_HELPERS_H_
