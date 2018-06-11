#!/usr/bin/python

# This script checks whether a set of test runs matched the Gold baselines.
#
# It accepts a list of result directories that were previous generated
# by running a test suite (e.g. the 'corpus' tests). Each directory is assumed
# to contain a 'passfail.json' file (see gold.py). It parses all files and
# outputs a summary of the results.
# The return value indicates whether all tests matched expectations (0) or
# whether there was at least one failure (1).

import json
import os
import sys

def main(result_dirs):
  results = {}
  missing_files = []

  # Parse all files and group them by matching results
  for result_dir in result_dirs:
    # Load the json data from the result directory.
    passfail_file = os.path.join(result_dir, 'passfail.json')
    print "Parsing pass/fail file: %s" % passfail_file
    if not os.path.exists(passfail_file):
      missing_files.append(passfail_file)
      continue

    with open(passfail_file) as f:
      pf = json.load(f)
    by_matched = {}
    for test_name, matched in pf:
      by_matched.setdefault(matched, set()).add(test_name)
    results[passfail_file] = by_matched

  # Print a summary of all input files
  for file, by_matched in results.iteritems():
    print "File: %s" % file
    print "Summary:"
    for matched in sorted(by_matched.keys()):
      print "%15s : %d tests" % (matched, len(by_matched[matched]))
    print "\n"

  # Print the list of files that we didn't find.
  if len(missing_files) > 0:
    print "Missing files:"
    for file in missing_files:
      print "    Expected to find file '%s'" % file

  # Accumulate results
  no_baseline_count = 0
  mismatch_count = 0
  suppressed_count = 0

  if len(results) > 0:
    print "Test result details:"
    for file in sorted(results.keys()):
      by_matched = results[file]
      print "    Results for file: %s" % file
      for matched in sorted(by_matched.keys()):
        testNames = sorted(by_matched[matched])
        if matched == 'mismatch':
          mismatch_count += len(testNames)
        elif matched == 'no_baseline':
          no_baseline_count += len(testNames)
        elif matched == 'suppressed':
          suppressed_count += len(testNames)

        print "    '%s' Tests (%d):" % (matched, len(testNames))
        for testName in testNames:
          print "    ", testName
      print "\n\n"

  # Fail if there are missing files or we found tests that do not match or
  # have no baseline at all.
  fail = ((len(missing_files) > 0) or
          (no_baseline_count > 0) or
          (mismatch_count > 0))
  if fail:
    print 'Failure: Some tests did not match the baselines or some baselines are ' +\
          'missing\n'
  else:
    print 'Success: All baselines match\n'
  sys.exit(1 if fail else 0)

if __name__=='__main__':
  if len(sys.argv) <= 1:
    print 'Error: At least one result directory is required as argument. ' + \
          'Received none!\n'
    print 'Usage:'
    print sys.argv[0], ' result_dir [result_dir, ...]'
    print 'Each result_dir is expected to contain an \'passfail.json\' file\n\n'
    sys.exit(1)

  main(sys.argv[1:])
