#!/usr/bin/env python3
# Copyright 2024 The PDFium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Lists all the C++ source files.

Use GN to read out first-party targets and their source files.
"""

import subprocess
import sys


def _RunCommandGetStdout(command):
  result = subprocess.run(command, capture_output=True, check=True)
  return result.stdout


def _RunGnCommandGetStdout(sub_command, out_dir, args=None):
  command = ['gn', sub_command, out_dir]
  if args:
    command.extend(args)

  try:
    return _RunCommandGetStdout(command)
  except subprocess.CalledProcessError as e:
    if sub_command == 'desc' and e.stdout.startswith(
        b'Don\'t know how to display "sources"'):
      return b''
    raise e


def _IsExcludedTarget(target):
  EXCLUDED_PREFIXES = [
      b'//base',
      b'//build',
      b'//skia',
      b'//testing',
      b'//third_party',
      b'//v8',
  ]
  return any(target.startswith(prefix) for prefix in EXCLUDED_PREFIXES)


def main():
  if len(sys.argv) != 2:
    print('Wrong number of arguments')
    return 1

  out_dir = sys.argv[1]
  TARGET_TYPES = [
      'executable',
      'shared_library',
      'source_set',
      'static_library',
  ]
  targets = []
  for target_type in TARGET_TYPES:
    targets.extend([
        target for target in _RunGnCommandGetStdout(
            'ls', out_dir, ['--type=%s' % target_type]).splitlines()
        if not _IsExcludedTarget(target)
    ])

  sources = []
  for target in targets:
    output = _RunGnCommandGetStdout('desc', out_dir,
                                    [target.decode(), 'sources'])
    sources.extend(output.splitlines())

  sources.sort()
  for source in sources:
    print(source.removeprefix(b'//').decode())

  return 0


if __name__ == '__main__':
  sys.exit(main())
