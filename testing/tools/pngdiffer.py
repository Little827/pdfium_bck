#!/usr/bin/env python
# Copyright 2015 The PDFium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import distutils.spawn
import itertools
import os
import shutil
import sys

# pylint: disable=relative-import
import common


class PNGDiffer():

  def __init__(self, finder, reverse_byte_order):
    self.pdfium_diff_path = finder.ExecutablePath('pdfium_diff')
    self.os_name = finder.os_name
    self.reverse_byte_order = reverse_byte_order
    self.skiapaths_enabled = common.GetBooleanGnArg('pdf_use_skia_paths',
                                                    finder.build_dir)
    self.skia_enabled = self.skiapaths_enabled or common.GetBooleanGnArg(
        'pdf_use_skia', finder.build_dir)

  def CheckMissingTools(self, regenerate_expected):
    if (regenerate_expected and self.os_name == 'linux' and
        not distutils.spawn.find_executable('optipng')):
      return 'Please install "optipng" to regenerate expected images.'
    return None

  def GetActualFiles(self, input_filename, source_dir, working_dir):
    actual_paths = []
    path_templates = PathTemplates(input_filename, source_dir, working_dir)

    for page in itertools.count():
      actual_path = path_templates.GetActualPath(page)
      expected_paths = path_templates.GetExpectedPaths(self.os_name, page)
      if any(itertools.imap(os.path.exists, expected_paths)):
        actual_paths.append(actual_path)
      else:
        break
    return actual_paths

  def _ImageDiffError(self, expected_path, actual_path, orig_error):
    if os.path.exists(expected_path):
      cmd = [self.pdfium_diff_path]
      if self.reverse_byte_order:
        cmd.append('--reverse-byte-order')
      cmd.extend([expected_path, actual_path])
      error = common.RunCommand(cmd)
    elif orig_error:
      # Get the error number from previous check.
      error = orig_error
    else:
      # Return error of missing expected file.
      error = 1
    return error

  def HasDifferences(self, input_filename, source_dir, working_dir):
    path_templates = PathTemplates(input_filename, source_dir, working_dir)

    for page in itertools.count():
      actual_path = path_templates.GetActualPath(page)
      expected_path = path_templates.GetExpectedPath(page)
      # PDFium tests should be platform independent. Platform based results are
      # used to capture platform dependent implementations.
      platform_expected_path = path_templates.GetPlatformExpectedPath(
          self.os_name, page)
      skia_expected_path = path_templates.GetSkiaExpectedPath(page)
      skia_platform_expected_path = path_templates.GetSkiaPlatformExpectedPath(
          self.os_name, page)
      skiapaths_expected_path = path_templates.GetSkiaPathsExpectedPath(page)
      skiapaths_platform_expected_path = \
          path_templates.GetSkiaPathsPlatformExpectedPath(self.os_name, page)

      expected_paths = path_templates.GetExpectedPaths(self.os_name, page)
      if not any(itertools.imap(os.path.exists, expected_paths)):
        if page == 0:
          print "WARNING: no expected results files for " + input_filename
        if os.path.exists(actual_path):
          print('FAILURE: Missing expected result for 0-based page %d of %s' %
                (page, input_filename))
          return True
        break
      print "Checking " + actual_path
      sys.stdout.flush()

      error = self._ImageDiffError(expected_path, actual_path, 0)
      if error:
        # When failed, we check against platform based results.
        error = self._ImageDiffError(platform_expected_path, actual_path, error)
        if error:
          if not self.skia_enabled:
            print "FAILURE: " + input_filename + "; " + str(error)
            return True

      # When Skia or SkiaPaths is enabled, check against Skia expected results.
      if error:
        error = self._ImageDiffError(skia_expected_path, actual_path, error)
        if error:
          error = self._ImageDiffError(skia_platform_expected_path, actual_path,
                                       error)
          if not self.skiapaths_enabled:
            print "FAILURE: " + input_filename + "; " + str(error)
            return True

      # If there is no match in Skia expected results, check against the
      # SkiaPaths specific expected results if SkiaPaths is enabled.
      if error:
        error = self._ImageDiffError(skiapaths_expected_path, actual_path,
                                     error)
        if error:
          error = self._ImageDiffError(skiapaths_platform_expected_path,
                                       actual_path, error)
          print "FAILURE: " + input_filename + "; " + str(error)
          return True

    return False

  def Regenerate(self, input_filename, source_dir, working_dir, platform_only):
    path_templates = PathTemplates(input_filename, source_dir, working_dir)

    for page in itertools.count():
      # Loop through the generated page images. Stop when there is a page
      # missing a png, which means the document ended.
      actual_path = path_templates.GetActualPath(page)
      if not os.path.isfile(actual_path):
        break

      platform_expected_path = path_templates.GetPlatformExpectedPath(
          self.os_name, page)

      # If there is a platform expected png, we will overwrite it. Otherwise,
      # overwrite the generic png in "all" mode, or do nothing in "platform"
      # mode.
      if os.path.exists(platform_expected_path):
        expected_path = platform_expected_path
      elif not platform_only:
        expected_path = path_templates.GetExpectedPath(page)
      else:
        continue

      shutil.copyfile(actual_path, expected_path)
      common.RunCommand(['optipng', expected_path])


ACTUAL_TEMPLATE = '.pdf.%d.png'
EXPECTED_TEMPLATE = '_expected' + ACTUAL_TEMPLATE
PLATFORM_EXPECTED_TEMPLATE = '_expected_%s' + ACTUAL_TEMPLATE
SKIA_EXPECTED_TEMPLATE = '_expected_skia' + ACTUAL_TEMPLATE
SKIA_PLATFORM_EXPECTED_TEMPLATE = '_expected_skia_%s' + ACTUAL_TEMPLATE
SKIAPATHS_EXPECTED_TEMPLATE = '_expected_skiapaths' + ACTUAL_TEMPLATE
SKIAPATHS_PLATFORM_EXPECTED_TEMPLATE = '_expected_skiapaths_%s' + \
                                       ACTUAL_TEMPLATE


class PathTemplates(object):

  def __init__(self, input_filename, source_dir, working_dir):
    input_root, _ = os.path.splitext(input_filename)
    self.actual_path_template = os.path.join(working_dir,
                                             input_root + ACTUAL_TEMPLATE)
    self.expected_path = os.path.join(source_dir,
                                      input_root + EXPECTED_TEMPLATE)
    self.platform_expected_path = os.path.join(
        source_dir, input_root + PLATFORM_EXPECTED_TEMPLATE)
    self.skia_expected_path = os.path.join(source_dir,
                                           input_root + SKIA_EXPECTED_TEMPLATE)
    self.skia_platform_expected_path = os.path.join(
        source_dir, input_root + SKIA_PLATFORM_EXPECTED_TEMPLATE)
    self.skiapaths_expected_path = os.path.join(
        source_dir, input_root + SKIAPATHS_EXPECTED_TEMPLATE)
    self.skiapaths_platform_expected_path = os.path.join(
        source_dir, input_root + SKIAPATHS_PLATFORM_EXPECTED_TEMPLATE)

  def GetActualPath(self, page):
    return self.actual_path_template % page

  def GetExpectedPath(self, page):
    return self.expected_path % page

  def GetPlatformExpectedPath(self, platform, page):
    return self.platform_expected_path % (platform, page)

  def GetSkiaExpectedPath(self, page):
    return self.skia_expected_path % (page)

  def GetSkiaPlatformExpectedPath(self, platform, page):
    return self.skia_platform_expected_path % (platform, page)

  def GetSkiaPathsExpectedPath(self, page):
    return self.skiapaths_expected_path % (page)

  def GetSkiaPathsPlatformExpectedPath(self, platform, page):
    return self.skiapaths_platform_expected_path % (platform, page)

  def GetExpectedPaths(self, platform, page):
    expected_paths = [
        self.GetExpectedPath(page),
        self.GetPlatformExpectedPath(platform, page),
        self.GetSkiaExpectedPath(page),
        self.GetSkiaPlatformExpectedPath(platform, page),
        self.GetSkiaPathsExpectedPath(page),
        self.GetSkiaPathsPlatformExpectedPath(platform, page)
    ]
    return expected_paths
