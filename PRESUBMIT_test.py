#!/usr/bin/env python
# Copyright 2020 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import unittest

import PRESUBMIT
from presubmit_test_mocks import (MockInputApi, MockOutputApi, MockFile)

class CheckChangeOnUploadTest(unittest.TestCase):

  def testCheckPNGFormat(self):
    print 'testCheckPNGFormat'
    mock_input_api = MockInputApi()
    mock_output_api = MockOutputApi()

    mock_input_api.files = [
        MockFile('test_expected.pdf.0.png'),
        MockFile('test_expected_win.pdf.1.png'),
        MockFile('test_expected_skia.pdf.2.png'),
        MockFile('test_expected_skiapaths.pdf.3.png'),
        MockFile('test_expected_skia_mac.pdf.4.png'),
        MockFile('test_expected_skiapaths_win.pdf.5.png'),
        MockFile('notpng.cc'), # Check will be skipped for non-PNG files
        MockFile('test0.pdf.0.png'), # Missing 'expected'
        MockFile('test1_expected.0.png'), # Missing 'pdf'
        MockFile('test2_expected.pdf.png'), # Missing page number
        MockFile('test3_expected.pdf.x.png'), # Wrong character for page number
        MockFile('test4_expected_mac_skia.pdf.png'), # Wrong order
        MockFile('test5_expected_useskia.pdf.png'), # Wrong path template
    ]

    errors = PRESUBMIT._CheckPNGFormat(mock_input_api, mock_output_api)
    self.assertEqual(6, len(errors))
    self.assertFalse('notpng.cc' in str(errors[0]))
    self.assertTrue('test0.pdf.0.png' in str(errors[0]))
    self.assertTrue('test1_expected.0.png' in str(errors[1]))
    self.assertTrue('test2_expected.pdf.png' in str(errors[2]))
    self.assertTrue('test3_expected.pdf.x.png' in str(errors[3]))
    self.assertTrue('test4_expected_mac_skia.pdf.png' in str(errors[4]))
    self.assertTrue('test5_expected_useskia.pdf.png' in str(errors[5]))


if __name__ == '__main__':
  unittest.main()
