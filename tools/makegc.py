#!/usr/bin/env python
#
# Copyright 2020 The PDFium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Rewrites class descriptions to force garbage-collected allocation.
Usage: makegc.py <files...>
"""

import optparse
import os
import re
import sys


class ParserState:
  OUTSIDE_CLASS = 1
  FOUND_CLASS = 2
  FOUND_PUBLIC = 3
  OUTPUT_FRIEND = 4
  FOUND_PRIVATE = 5
  OUTPUT_SAVED = 6


def process_file(input_path, output_path, trace):
  try:
    state = ParserState.OUTSIDE_CLASS
    with open(input_path, 'rb') as infile:
      with open(output_path, 'wb') as outfile:
        for line in infile:
          if trace:
            print state, line
          print_line = True
          if state == ParserState.OUTSIDE_CLASS:
            match = re.match(r'^class\s+(\w*)\s', line)
            if match:
              class_name = match.group(1)
              saved = ''
              state = ParserState.FOUND_CLASS
          elif state == ParserState.FOUND_CLASS:
            match = re.match(r'^\s+public:', line)
            if match:
              state = ParserState.FOUND_PUBLIC
          elif state == ParserState.FOUND_PUBLIC:
            match = re.match(r'^\s+' + class_name + '\(', line)
            if match:
              saved += line
              print_line = False
              outfile.write('  ALLOCATE_VIA_MAKE_GARBAGE_COLLECTED;\n')
              state = ParserState.OUTPUT_FRIEND
          elif state == ParserState.OUTPUT_FRIEND:
            match = re.match(r'^\s+' + class_name + '\(', line)
            if match:
              saved += line
              print_line = False
            else:
              match = re.match(r'^\s+private:', line)
              if match:
                state = ParserState.FOUND_PRIVATE
              else:
                match = re.match(r'^};', line)
                if match:
                  outfile.write('\n')
                  outfile.write(' private:\n')
                  outfile.write(saved)
                  state = ParserState.OUTSIDE_CLASS
          elif state == ParserState.FOUND_PRIVATE:
            outfile.write(saved)
            state = ParserState.OUTPUT_SAVED
            match = re.match(r'^};', line)
            if match:
              state = ParserState.OUTSIDE_CLASS
          elif state == ParserState.OUTPUT_SAVED:
            match = re.match(r'^};', line)
            if match:
              state = ParserState.OUTSIDE_CLASS
          if print_line:
            outfile.write(line)
  except IOError:
    print >> sys.stderr, 'failed to process %s' % input_path


def main():
  parser = optparse.OptionParser()
  options, args = parser.parse_args()
  for input_file_path in args:
    temp_file_path = input_file_path + '.tmp'
    process_file(input_file_path, temp_file_path, False)
    os.rename(temp_file_path, input_file_path)
  return 0


if __name__ == '__main__':
  sys.exit(main())
