# Copyright 2015 The PDFium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import os
import shlex
import shutil
import ssl
import urllib2

from skia_gold import pdfium_skia_gold_properties
from skia_gold import pdfium_skia_gold_session_manager

GS_BUCKET = 'skia-pdfium-gm'

def _ParseKeyValuePairs(kv_str):
  """
  Parses a string of the type 'key1 value1 key2 value2' into a dict.
  """
  kv_pairs = shlex.split(kv_str)
  if len(kv_pairs) % 2:
    raise ValueError('Uneven number of key/value pairs. Got %s' % kv_str)
  return {kv_pairs[i]: kv_pairs[i + 1] for i in xrange(0, len(kv_pairs), 2)}

def add_skia_gold_args(parser):
    group = parser.add_argument_group('Skia Gold Arguments')
    group.add_argument('--git-revision', help='Revision being tested.', default=None)
    group.add_argument(
        '--gerrit-issue', help='For Skia Gold integration. Gerrit issue ID.', default='')
    group.add_argument(
        '--gerrit-patchset',
        help='For Skia Gold integration. Gerrit patch set number.',
        default='')
    group.add_argument(
        '--buildbucket-id', help='For Skia Gold integration. Buildbucket build ID.', default='')
    group.add_argument(
        '--bypass-skia-gold-functionality',
        action='store_true',
        default=False,
        help='Bypass all interaction with Skia Gold, effectively disabling the '
        'image comparison portion of any tests that use Gold. Only meant to '
        'be used in case a Gold outage occurs and cannot be fixed quickly.')
    local_group = group.add_mutually_exclusive_group()
    local_group.add_argument(
        '--local-pixel-tests',
        action='store_true',
        default=None,
        help='Specifies to run the test harness in local run mode or not. When '
        'run in local mode, uploading to Gold is disabled and links to '
        'help with local debugging are output. Running in local mode also '
        'implies --no-luci-auth. If both this and --no-local-pixel-tests are '
        'left unset, the test harness will attempt to detect whether it is '
        'running on a workstation or not and set this option accordingly.')
    local_group.add_argument(
        '--no-local-pixel-tests',
        action='store_false',
        dest='local_pixel_tests',
        help='Specifies to run the test harness in non-local (bot) mode. When '
        'run in this mode, data is actually uploaded to Gold and triage links '
        'arge generated. If both this and --local-pixel-tests are left unset, '
        'the test harness will attempt to detect whether it is running on a '
        'workstation or not and set this option accordingly.')
    group.add_argument(
        '--no-luci-auth',
        action='store_true',
        default=False,
        help='Don\'t use the service account provided by LUCI for '
        'authentication for Skia Gold, instead relying on gsutil to be '
        'pre-authenticated. Meant for testing locally instead of on the bots.')
    group.add_argument(
        '--gold_key',
        default='',
        dest="gold_key",
        help='Key value pairs of config data such like the hardware/software '
        'configuration the image was produced on.')
    group.add_argument(
        '--gold_output_dir',
        default='',
        dest="gold_output_dir",
        help='Path of where to write the JSON output to be '
        'uploaded to Gold.')

class SkiaTester(object):

  def __init__(self, source_type, skia_gold_args):
    """
    source_type: source_type (=corpus) field used for all results.
    skia_gold_args: Parsed arguments from argparse.ArgumentParser
    """
    self._source_type = source_type
    self._output_dir = skia_gold_args.gold_output_dir
    self._keys = _ParseKeyValuePairs(skia_gold_args.gold_key) 
    self._skia_gold_args = skia_gold_args
    self._skia_gold_session_manager = None
    self._skia_gold_properties = None

    # make sure the output directory exists and is empty.
    if os.path.exists(self._output_dir):
      shutil.rmtree(self._output_dir, ignore_errors=True)
    os.makedirs(self._output_dir)
    if os.path.exists(self._output_dir):
      print('exists')

  def GetSkiaGoldProperties(self):
    if not self._skia_gold_properties:
      self._skia_gold_properties = pdfium_skia_gold_properties.PDFiumSkiaGoldProperties(self._skia_gold_args)
    return self._skia_gold_properties

  def GetSkiaGoldSessionManager(self):
    if not self._skia_gold_session_manager:
      self._skia_gold_session_manager = pdfium_skia_gold_session_manager.PDFiumSkiaGoldSessionManager(self._output_dir, self.GetSkiaGoldProperties())
    return self._skia_gold_session_manager

  def UploadTestResultToSkiaGold(self, image_name, image_path):
    gold_session = self.GetSkiaGoldSessionManager()\
        .GetSkiaGoldSession(self._keys, corpus=self._source_type, bucket=GS_BUCKET)
    gold_properties = self.GetSkiaGoldProperties()
    use_luci = not (gold_properties.local_pixel_tests
                    or gold_properties.no_luci_auth)

    status, error = gold_session.RunComparison(
        name=image_name, png_file=image_path, use_luci=use_luci)

    print(status)


if __name__ == '__main__':
  _Example()
