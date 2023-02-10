#!/usr/bin/env python3
# Copyright 2015 The PDFium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from dataclasses import dataclass
import itertools
import os
import shutil
import subprocess
import sys

_PNG_OPTIMIZER = 'optipng'

_COMMON_SUFFIX_ORDER = ('_{os}', '')
_AGG_SUFFIX_ORDER = ('_agg_{os}', '_agg') + _COMMON_SUFFIX_ORDER
_SKIA_SUFFIX_ORDER = ('_skia_{os}', '_skia') + _COMMON_SUFFIX_ORDER


@dataclass
class ImageDiff:
  """Details about an image diff.

  Attributes:
    actual_path: Path to the actual image file.
    expected_path: Path to the expected image file, or `None` if no matches.
    diff_path: Path to the diff image file, or `None` if no diff.
    reason: Optional reason for the diff.
  """
  actual_path: str
  expected_path: str = None
  diff_path: str = None
  reason: str = None

class PNGDiffer():

  def __init__(self, finder, features, reverse_byte_order):
    self.pdfium_diff_path = finder.ExecutablePath('pdfium_diff')
    self.os_name = finder.os_name
    self.reverse_byte_order = reverse_byte_order
    if 'SKIA' in features:
      self.suffix_order = _SKIA_SUFFIX_ORDER
    else:
      self.suffix_order = _AGG_SUFFIX_ORDER

  def CheckMissingTools(self, regenerate_expected):
    if regenerate_expected and not shutil.which(_PNG_OPTIMIZER):
      return f'Please install "{_PNG_OPTIMIZER}" to regenerate expected images.'
    return None

  def GetActualFiles(self, input_filename, source_dir, working_dir):
    actual_paths = []
    path_templates = _PathTemplates(input_filename, source_dir, working_dir,
                                    self.os_name, self.suffix_order)

    for page in itertools.count():
      actual_path = path_templates.GetActualPath(page)
      if path_templates.GetExpectedPath(page, default_to_base=False):
        actual_paths.append(actual_path)
      else:
        break
    return actual_paths

  def _RunCommand(self, cmd):
    try:
      subprocess.run(cmd, capture_output=True, check=True)
      return None
    except subprocess.CalledProcessError as e:
      return e

  def _RunImageCompareCommand(self, image_diff):
    cmd = [self.pdfium_diff_path]
    if self.reverse_byte_order:
      cmd.append('--reverse-byte-order')
    cmd.extend([image_diff.actual_path, image_diff.expected_path])
    return self._RunCommand(cmd)

  def _RunImageDiffCommand(self, image_diff):
    # TODO(crbug.com/pdfium/1925): Diff mode ignores --reverse-byte-order.
    return self._RunCommand([
        self.pdfium_diff_path, '--subtract', image_diff.actual_path,
        image_diff.expected_path, image_diff.diff_path
    ])

  def ComputeDifferences(self, input_filename, source_dir, working_dir):
    """Computes differences between actual and expected image files.

    Returns:
      A list of `ImageDiff` instances, one per differing page.
    """
    image_diffs = []

    path_templates = _PathTemplates(input_filename, source_dir, working_dir,
                                    self.os_name, self.suffix_order)
    for page in itertools.count():
      page_diff = ImageDiff(actual_path=path_templates.GetActualPath(page))
      if not os.path.exists(page_diff.actual_path):
        break

      expected_path = path_templates.GetExpectedPath(page, default_to_base=True)
      if os.path.exists(expected_path):
        page_diff.expected_path = expected_path

        compare_error = self._RunImageCompareCommand(page_diff)
        if not compare_error:
          # Proceed to next page
          continue
        page_diff.reason = str(compare_error)

        # TODO(crbug.com/pdfium/1925): Compare and diff in a single invocation.
        page_diff.diff_path = path_templates.GetDiffPath(page)
        if not self._RunImageDiffCommand(page_diff):
          print(f'WARNING: No diff for {page_diff.actual_path}')
          page_diff.diff_path = None
      else:
        if page == 0:
          print(f'WARNING: no expected results files for {input_filename}')
        page_diff.reason = f'{expected_path} does not exist'

      image_diffs.append(page_diff)

    return image_diffs

  def Regenerate(self, input_filename, source_dir, working_dir):
    path_templates = _PathTemplates(input_filename, source_dir, working_dir,
                                    self.os_name, self.suffix_order)
    for page in itertools.count():
      # Find existing expectations.
      existing_expected_paths = list(
          filter(os.path.exists, path_templates.GetExpectedPaths(page)))

      # Make sure the actual page exists.
      page_diff = ImageDiff(actual_path=path_templates.GetActualPath(page))
      if not os.path.exists(page_diff.actual_path):
        if existing_expected_paths:
          print(f'WARNING: {input_filename} has extra expected page {page}')
        break

      # Compare against existing expectations.
      first_match = None
      multiple_matches = False
      for index, expected_path in enumerate(existing_expected_paths):
        page_diff.expected_path = expected_path
        if self._RunImageCompareCommand(page_diff):
          # Not a match.
          continue

        if first_match is None:
          first_match = index
          assert first_match != 0
          if first_match != 1:
            print(f'WARNING: {input_filename}.{page} has non-adjacent match')
        elif not multiple_matches:
          multiple_matches = True
          print(f'WARNING: {input_filename}.{page} has redundant matches')

      # Try to use an existing expectation.
      if first_match is not None:
        os.remove(existing_expected_paths[0])
        for expected_path in existing_expected_paths[1:first_match]:
          os.rename(expected_path, expected_path + '.bak')

        # Proceed to next page.
        continue

      # Regenerate the most specific expected path that exists. If there are no
      # existing expectations, regenerate the base case.
      expected_path = path_templates.GetExpectedPath(page)
      shutil.copyfile(actual_path, expected_path)
      self._RunCommand([_PNG_OPTIMIZER, expected_path])


_ACTUAL_TEMPLATE = '.pdf.%d.png'
_DIFF_TEMPLATE = '.pdf.%d.diff.png'


class _PathTemplates:

  def __init__(self, input_filename, source_dir, working_dir, os_name,
               suffix_order):
    input_root, _ = os.path.splitext(input_filename)
    self.actual_path_template = os.path.join(working_dir,
                                             input_root + _ACTUAL_TEMPLATE)
    self.diff_path_template = os.path.join(working_dir,
                                           input_root + _DIFF_TEMPLATE)

    # Pre-create the available templates from most to least specific. We
    # generally expect the most specific case to match first.
    self.expected_templates = []
    for suffix in suffix_order:
      formatted_suffix = suffix.format(os=os_name)
      self.expected_templates.append(
          os.path.join(
              source_dir,
              f'{input_root}_expected{formatted_suffix}{_ACTUAL_TEMPLATE}'))
    assert self.expected_templates

  def GetActualPath(self, page):
    return self.actual_path_template % page

  def GetDiffPath(self, page):
    return self.diff_path_template % page

  def GetExpectedPaths(self, page):
    return [template % page for template in self.expected_templates]

  def GetExpectedPath(self, page, default_to_base=True):
    """Returns the most specific expected path that exists."""
    last_not_found_expected_path = None
    for expected_path in self.GetExpectedPaths(page):
      if os.path.exists(expected_path):
        return expected_path
      last_not_found_expected_path = expected_path
    return last_not_found_expected_path if default_to_base else None
