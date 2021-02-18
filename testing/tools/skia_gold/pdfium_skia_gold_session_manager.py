#!/usr/bin/env python
# Copyright 2021 The PDFium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""PDFium implementation of //build/skia_gold_common/skia_gold_session_manager.py."""

import os
import subprocess
import sys

import path_utils
path_utils.AddDirToPathIfNeeded(path_utils.GetPDFiumDir(), 'build')
from skia_gold_common import output_managerless_skia_gold_session as omsgs
from skia_gold_common import skia_gold_session_manager as sgsm

SKIA_PDF_INSTANCE = 'pdfium'


class PDFiumSkiaGoldSessionManager(sgsm.SkiaGoldSessionManager):

  @staticmethod
  def GetSessionClass():
    return PDFiumSkiaGoldSession

  @staticmethod
  def _GetDefaultInstance():
    return SKIA_PDF_INSTANCE


class PDFiumSkiaGoldSession(omsgs.OutputManagerlessSkiaGoldSession):

  def _GetDiffGoldInstance(self):
    return str(self._instance)
