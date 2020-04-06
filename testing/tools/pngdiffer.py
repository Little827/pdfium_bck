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


class CheckMode:
  DEFAULT = 0
  SKIA = 1
  SKIAPATHS = 2


class FindMatchStatus:
  IN_PROGRESS = 0
  NOT_FOUND = 1
  FOUND = 2


class NotFoundError(Exception):
  """Raised when file doesn't exist"""
  pass


class PNGDiffer():

  def __init__(self, finder, features, reverse_byte_order):
    self.pdfium_diff_path = finder.ExecutablePath('pdfium_diff')
    self.os_name = finder.os_name
    self.reverse_byte_order = reverse_byte_order
    self.skiapaths_enabled = 'SKIAPATHS' in features
    self.skia_enabled = 'SKIA' in features or self.skiapaths_enabled

  def CheckMissingTools(self, regenerate_expected):
    if (regenerate_expected and self.os_name == 'linux' and
        not distutils.spawn.find_executable('optipng')):
      return 'Please install "optipng" to regenerate expected images.'
    return None

  def GetActualFiles(self, input_filename, source_dir, working_dir):
    actual_paths = []
    path_templates = PathTemplates(input_filename, source_dir, working_dir,
                                   self.skia_enabled)

    for page in itertools.count():
      actual_path = path_templates.GetActualPath(page)
      expected_paths = path_templates.GetExpectedPaths(self.os_name, page)
      if any(itertools.imap(os.path.exists, expected_paths)):
        actual_paths.append(actual_path)
      else:
        break
    return actual_paths

  def _RunImageDiffCommand(self, expected_path, actual_path):
    if not os.path.exists(expected_path):
      return NotFoundError('%s does not exist.' % expected_path)

    cmd = [self.pdfium_diff_path]
    if self.reverse_byte_order:
      cmd.append('--reverse-byte-order')
    cmd.extend([expected_path, actual_path])
    return common.RunCommand(cmd)

  def _FindMatchProcessStatus(self, input_filename, path_templates, page, mode):
    actual_path = path_templates.GetActualPath(page)
    expected_path = path_templates.GetExpectedPathByCheckMode(page, mode)
    platform_expected_path = path_templates.GetExpectedPathByCheckMode(
        page, mode, self.os_name)

    error = self._RunImageDiffCommand(expected_path, actual_path)
    if not error:
      return FindMatchStatus.FOUND

    # When failed, we check against platform based results.
    platform_error = self._RunImageDiffCommand(platform_expected_path,
                                               actual_path)
    if not platform_error:
      return FindMatchStatus.FOUND

    # Update error code. No need to overwrite the previous error code if
    # |platform_expected_path| doesn't exist.
    if not isinstance(platform_error, NotFoundError):
      error = platform_error

    if mode == CheckMode.SKIAPATHS or (mode == CheckMode.DEFAULT and
                                       not self.skia_enabled) or (
                                           mode == CheckMode.SKIA and
                                           not self.skiapaths_enabled):
      # Reach ending conditions, print error message.
      print "FAILURE: " + input_filename + "; " + str(error)
      return FindMatchStatus.NOT_FOUND

    return FindMatchStatus.IN_PROGRESS

  def HasDifferences(self, input_filename, source_dir, working_dir):
    path_templates = PathTemplates(input_filename, source_dir, working_dir,
                                   self.skia_enabled)
    for page in itertools.count():
      actual_path = path_templates.GetActualPath(page)
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

      mode = CheckMode.DEFAULT
      # Check through regular/skia/skiapaths expected results to find a match.
      while mode <= CheckMode.SKIAPATHS:
        status = self._FindMatchProcessStatus(input_filename, path_templates,
                                              page, mode)
        if status == FindMatchStatus.IN_PROGRESS:
          mode = mode + 1
          continue

        if status == FindMatchStatus.FOUND:
          break

        return True

    return False

  # TODO(nigi): Add handling for automatically generate expected result for
  # Skia/Skiapaths
  def Regenerate(self, input_filename, source_dir, working_dir, platform_only):
    path_templates = PathTemplates(input_filename, source_dir, working_dir,
                                   self.skia_enabled)

    for page in itertools.count():
      # Loop through the generated page images. Stop when there is a page
      # missing a png, which means the document ended.
      actual_path = path_templates.GetActualPath(page)
      if not os.path.isfile(actual_path):
        break

      platform_expected_path = \
          path_templates.GetExpectedPathByCheckMode(
              page, CheckMode.DEFAULT, self.os_name)

      # If there is a platform expected png, we will overwrite it. Otherwise,
      # overwrite the generic png in "all" mode, or do nothing in "platform"
      # mode.
      if os.path.exists(platform_expected_path):
        expected_path = platform_expected_path
      elif not platform_only:
        expected_path = path_templates.GetExpectedPathByCheckMode(
            page, CheckMode.DEFAULT)
      else:
        continue

      shutil.copyfile(actual_path, expected_path)
      common.RunCommand(['optipng', expected_path])


ACTUAL_TEMPLATE = '.pdf.%d.png'

class PathTemplates(object):

  def __init__(self, input_filename, source_dir, working_dir, skia_enabled):
    input_root, _ = os.path.splitext(input_filename)
    self.actual_path_template = os.path.join(working_dir,
                                             input_root + ACTUAL_TEMPLATE)
    self.source_dir = source_dir
    self.input_root = input_root
    self.skia_enabled = skia_enabled

  def GetActualPath(self, page):
    return self.actual_path_template % page

  def GetExpectedPathByCheckMode(self, page, mode, platform=None):
    if mode == CheckMode.DEFAULT:
      expected_str = '_expected'
    elif mode == CheckMode.SKIA:
      expected_str = '_expected_skia'
    else:
      expected_str = '_expected_skiapaths'

    if platform:
      expected_str = expected_str + '_' + platform
    path = os.path.join(self.source_dir,
                        self.input_root + expected_str + ACTUAL_TEMPLATE)
    return path % page

  def GetExpectedPaths(self, platform, page):
    expected_paths = [
        self.GetExpectedPathByCheckMode(page, CheckMode.DEFAULT),
        self.GetExpectedPathByCheckMode(page, CheckMode.DEFAULT, platform),
    ]
    if self.skia_enabled:
      expected_paths.extend([
          self.GetExpectedPathByCheckMode(page, CheckMode.SKIA),
          self.GetExpectedPathByCheckMode(page, CheckMode.SKIA, platform),
          self.GetExpectedPathByCheckMode(page, CheckMode.SKIAPATHS),
          self.GetExpectedPathByCheckMode(page, CheckMode.SKIAPATHS, platform),
      ])
    return expected_paths
