#!/usr/bin/env python
# Copyright 2021 The PDFium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""PDFium implementation of //build/skia_gold_common/skia_gold_session.py."""

# pylint: disable=relative-import
import path_util
path_util.AddDirToPathIfNeeded(path_util.GetPDFiumDir(), 'build')
from skia_gold_common import output_managerless_skia_gold_session as omsgs


# ComparisonResults nested inside the SkiaGoldSession causes issues with
# multiprocessing and pickling, so it was moved out here.
class PDFiumComparisonResults(object):
  """Struct-like object for storing results of an image comparison."""

  def __init__(self):
    self.public_triage_link = None
    self.internal_triage_link = None
    self.triage_link_omission_reason = None
    self.local_diff_given_image = None
    self.local_diff_closest_image = None
    self.local_diff_diff_image = None


class PDFiumSkiaGoldSession(omsgs.OutputManagerlessSkiaGoldSession):

  def _GetDiffGoldInstance(self):
    return str(self._instance)

  def ComparisonResults(self):
    return PDFiumComparisonResults()

  def GetTriageLinks(self, name):
    """Gets the triage links for the given image.

    Args:
      name: The name of the image to retrieve the triage link for.

    Returns:
      A tuple (public, internal). |public| is a string containing the triage
      link for the public Gold instance if it is available, or None if it is not
      available for some reason. |internal| is the same as |public|, but
      containing a link to the internal Gold instance. The reason for links not
      being available can be retrieved using GetTriageLinkOmissionReason.
    """
    comparison_results = self._comparison_results.get(name, ComparisonResults())
    return (comparison_results.public_triage_link,
            comparison_results.internal_triage_link)
