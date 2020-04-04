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
  START = 1
  CHECK_SKIA = 2
  CHECK_SKIAPATHS = 3


class MatchFound(Exception):
  """Raised when a match is found from expected result(s)"""
  pass


class NotFoundError(Exception):
  """Raised when file doesn't exist"""
  pass


class PNGDiffer():

  def __init__(self, finder, features, reverse_byte_order):
    self.check_mode = CheckMode.START
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
    path_templates = PathTemplates(input_filename, source_dir, working_dir)

    for page in itertools.count():
      actual_path = path_templates.GetActualPath(page)
      expected_paths = path_templates.GetExpectedPaths(self.os_name, page,
                                                       self.skia_enabled)
      if any(itertools.imap(os.path.exists, expected_paths)):
        actual_paths.append(actual_path)
      else:
        break
    return actual_paths

  def _FindMatchProcessDone(self, input_filename, path_templates, page, mode):
    actual_path = path_templates.GetActualPath(page)
    expected_path = path_templates.GetExpectedPathByCheckMode(page, mode)
    platform_expected_path = path_templates.GetPlatformExpectedPathByCheckMode(
        page, self.os_name, mode)

    error = self._RunImageDiffCommand(expected_path, actual_path)
    if not error:
      return MatchFound()

    # When failed, we check against platform based results.
    platform_error = self._RunImageDiffCommand(platform_expected_path,
                                               actual_path)
    if not platform_error:
      return MatchFound()

    # Update error code. No need to overwrite the previous error code if
    # |platform_expected_path| doesn't exist.
    if not isinstance(platform_error, NotFoundError):
      error = platform_error

    end_condition = mode == CheckMode.CHECK_SKIAPATHS or (
        mode == CheckMode.START and
        not self.skia_enabled) or (mode == CheckMode.CHECK_SKIA and
                                   not self.skiapaths_enabled)

    if end_condition:
      # Reach ending conditions, print error message.
      print "FAILURE: " + input_filename + "; " + str(error)
      return True

    return False

  def _RunImageDiffCommand(self, expected_path, actual_path):
    if not os.path.exists(expected_path):
      return NotFoundError('%s does not exist.' % expected_path)

    cmd = [self.pdfium_diff_path]
    if self.reverse_byte_order:
      cmd.append('--reverse-byte-order')
    cmd.extend([expected_path, actual_path])
    return common.RunCommand(cmd)

  def HasDifferences(self, input_filename, source_dir, working_dir):
    path_templates = PathTemplates(input_filename, source_dir, working_dir)
    for page in itertools.count():
      actual_path = path_templates.GetActualPath(page)
      expected_paths = path_templates.GetExpectedPaths(self.os_name, page,
                                                       self.skia_enabled)
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

      mode = CheckMode.START
      # Check through regular/skia/skiapaths expected results to find a match.
      while mode <= CheckMode.CHECK_SKIAPATHS:
        is_done = self._FindMatchProcessDone(input_filename, path_templates,
                                             page, mode)
        if not is_done:
          mode = mode + 1
          continue

        if isinstance(is_done, MatchFound):
          break
        else:
          return True

    return False

  # TODO(nigi): Add handling for automatically generate expected result for
  # Skia/Skiapaths
  def Regenerate(self, input_filename, source_dir, working_dir, platform_only):
    path_templates = PathTemplates(input_filename, source_dir, working_dir)

    for page in itertools.count():
      # Loop through the generated page images. Stop when there is a page
      # missing a png, which means the document ended.
      actual_path = path_templates.GetActualPath(page)
      if not os.path.isfile(actual_path):
        break

      platform_expected_path = \
          path_templates.GetPlatformExpectedPathByCheckMode(
              page, self.os_name, CheckMode.START)

      # If there is a platform expected png, we will overwrite it. Otherwise,
      # overwrite the generic png in "all" mode, or do nothing in "platform"
      # mode.
      if os.path.exists(platform_expected_path):
        expected_path = platform_expected_path
      elif not platform_only:
        expected_path = path_templates.GetExpectedPathByCheckMode(
            page, CheckMode.START)
      else:
        continue

      shutil.copyfile(actual_path, expected_path)
      common.RunCommand(['optipng', expected_path])


ACTUAL_TEMPLATE = '.pdf.%d.png'

class PathTemplates(object):

  def __init__(self, input_filename, source_dir, working_dir):
    input_root, _ = os.path.splitext(input_filename)
    self.actual_path_template = os.path.join(working_dir,
                                             input_root + ACTUAL_TEMPLATE)
    self.source_dir = source_dir
    self.input_root = input_root

  def GetActualPath(self, page):
    return self.actual_path_template % page

  def GetExpectedTemplate(self, mode, platform):
    if mode is CheckMode.START:
      expected_str = '_expected'
    elif mode is CheckMode.CHECK_SKIA:
      expected_str = '_expected_skia'
    elif mode is CheckMode.CHECK_SKIAPATHS:
      expected_str = '_expected_skiapaths'
    else:
      return UnknownModeError()

    if platform:
      expected_str = expected_str + '_' + platform
    return expected_str + ACTUAL_TEMPLATE

  def GetExpectedPathByCheckMode(self, page, mode):
    expected_template = self.GetExpectedTemplate(mode, None)
    path = os.path.join(self.source_dir, self.input_root + expected_template)
    return path % page

  def GetPlatformExpectedPathByCheckMode(self, page, platform, mode):
    expected_template = self.GetExpectedTemplate(mode, platform)
    path = os.path.join(self.source_dir, self.input_root + expected_template)
    return path % page

  def GetExpectedPaths(self, platform, page, skia_enabled):
    expected_paths = [
        self.GetExpectedPathByCheckMode(page, CheckMode.START),
        self.GetPlatformExpectedPathByCheckMode(page, platform,
                                                CheckMode.START),
    ]
    if skia_enabled:
      expected_paths.extend([
          self.GetExpectedPathByCheckMode(page, CheckMode.CHECK_SKIA),
          self.GetPlatformExpectedPathByCheckMode(page, platform,
                                                  CheckMode.CHECK_SKIA),
          self.GetExpectedPathByCheckMode(page, CheckMode.CHECK_SKIAPATHS),
          self.GetPlatformExpectedPathByCheckMode(page, platform,
                                                  CheckMode.CHECK_SKIAPATHS)
      ])
    return expected_paths
