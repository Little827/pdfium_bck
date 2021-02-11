#!/usr/bin/env python
# Copyright 2021 The PDFium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""PDFium implementation of //build/skia_gold_common/skia_gold_properties.py."""

import os
import subprocess
import sys

# Add src dir to path to avoid having to set PYTHONPATH.
sys.path.append(
    os.path.abspath(
        os.path.join(
            os.path.dirname(__file__), os.path.pardir, os.path.pardir,
            os.path.pardir)))

from testing.tools import common

common.AddDirToPathIfNeeded(common.GetPDFiumDir(), 'build')
from skia_gold_common import skia_gold_properties

def print_check():
  print('hello')

class PDFiumSkiaGoldProperties(skia_gold_properties.SkiaGoldProperties):
  @staticmethod
  def _GetGitOriginMasterHeadSha1():
    try:
      return subprocess.check_output(['git', 'rev-parse', 'origin/master'],
                                     shell=_IsWin(),
                                     cwd=path_util.GetChromiumSrcDir()).strip()
    except subprocess.CalledProcessError:
      return None

def _IsWin():
  return sys.platform == 'win32'
