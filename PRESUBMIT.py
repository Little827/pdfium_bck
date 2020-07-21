# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Presubmit script for pdfium.

See http://dev.chromium.org/developers/how-tos/depottools/presubmit-scripts
for more details about the presubmit API built into depot_tools.
"""

LINT_FILTERS = [
  # Rvalue ref checks are unreliable.
  '-build/c++11',
  # Need to fix header names not matching cpp names.
  '-build/include_order',
  # Too many to fix at the moment.
  '-readability/casting',
  # Need to refactor large methods to fix.
  '-readability/fn_size',
  # Lots of usage to fix first.
  '-runtime/int',
  # Lots of non-const references need to be fixed
  '-runtime/references',
  # We are not thread safe, so this will never pass.
  '-runtime/threadsafe_fn',
  # Figure out how to deal with #defines that git cl format creates.
  '-whitespace/indent',
]


_INCLUDE_ORDER_WARNING = (
    'Your #include order seems to be broken. Remember to use the right '
    'collation (LC_COLLATE=C) and check\nhttps://google.github.io/styleguide/'
    'cppguide.html#Names_and_Order_of_Includes')


# Bypass the AUTHORS check for these accounts.
_KNOWN_ROBOTS = set() | set(
    '%s@skia-public.iam.gserviceaccount.com' % s for s in ('pdfium-autoroll',))


def _CheckUnwantedDependencies(input_api, output_api):
  """Runs checkdeps on #include statements added in this
  change. Breaking - rules is an error, breaking ! rules is a
  warning.
  """
  import sys
  # We need to wait until we have an input_api object and use this
  # roundabout construct to import checkdeps because this file is
  # eval-ed and thus doesn't have __file__.
  original_sys_path = sys.path
  try:
    def GenerateCheckdepsPath(base_path):
      return input_api.os_path.join(base_path, 'buildtools', 'checkdeps')

    presubmit_path = input_api.PresubmitLocalPath()
    presubmit_parent_path = input_api.os_path.dirname(presubmit_path)
    not_standalone_pdfium = \
        input_api.os_path.basename(presubmit_parent_path) == "third_party" and \
        input_api.os_path.basename(presubmit_path) == "pdfium"

    sys.path.append(GenerateCheckdepsPath(presubmit_path))
    if not_standalone_pdfium:
      presubmit_grandparent_path = input_api.os_path.dirname(
          presubmit_parent_path)
      sys.path.append(GenerateCheckdepsPath(presubmit_grandparent_path))

    import checkdeps
    from cpp_checker import CppChecker
    from rules import Rule
  except ImportError:
    return [output_api.PresubmitError(
        'Unable to run checkdeps, does pdfium/buildtools/checkdeps exist?')]
  finally:
    # Restore sys.path to what it was before.
    sys.path = original_sys_path

  added_includes = []
  for f in input_api.AffectedFiles():
    if not CppChecker.IsCppFile(f.LocalPath()):
      continue

    changed_lines = [line for line_num, line in f.ChangedContents()]
    added_includes.append([f.LocalPath(), changed_lines])

  deps_checker = checkdeps.DepsChecker(input_api.PresubmitLocalPath())

  error_descriptions = []
  warning_descriptions = []
  for path, rule_type, rule_description in deps_checker.CheckAddedCppIncludes(
      added_includes):
    description_with_path = '%s\n    %s' % (path, rule_description)
    if rule_type == Rule.DISALLOW:
      error_descriptions.append(description_with_path)
    else:
      warning_descriptions.append(description_with_path)

  results = []
  if error_descriptions:
    results.append(output_api.PresubmitError(
        'You added one or more #includes that violate checkdeps rules.',
        error_descriptions))
  if warning_descriptions:
    results.append(output_api.PresubmitPromptOrNotify(
        'You added one or more #includes of files that are temporarily\n'
        'allowed but being removed. Can you avoid introducing the\n'
        '#include? See relevant DEPS file(s) for details and contacts.',
        warning_descriptions))
  return results


def _CheckIncludeOrderForScope(scope, input_api, file_path, changed_linenums):
  """Checks that the lines in scope occur in the right order.

  1. C system files in alphabetical order
  2. C++ system files in alphabetical order
  3. Project's .h files
  """

  c_system_include_pattern = input_api.re.compile(r'\s*#include <.*\.h>')
  cpp_system_include_pattern = input_api.re.compile(r'\s*#include <.*>')
  custom_include_pattern = input_api.re.compile(r'\s*#include ".*')

  C_SYSTEM_INCLUDES, CPP_SYSTEM_INCLUDES, CUSTOM_INCLUDES = range(3)

  state = C_SYSTEM_INCLUDES

  previous_line = ''
  previous_line_num = 0
  problem_linenums = []
  out_of_order = " - line belongs before previous line"
  for line_num, line in scope:
    if c_system_include_pattern.match(line):
      if state != C_SYSTEM_INCLUDES:
        problem_linenums.append((line_num, previous_line_num,
            " - C system include file in wrong block"))
      elif previous_line and previous_line > line:
        problem_linenums.append((line_num, previous_line_num,
            out_of_order))
    elif cpp_system_include_pattern.match(line):
      if state == C_SYSTEM_INCLUDES:
        state = CPP_SYSTEM_INCLUDES
      elif state == CUSTOM_INCLUDES:
        problem_linenums.append((line_num, previous_line_num,
            " - c++ system include file in wrong block"))
      elif previous_line and previous_line > line:
        problem_linenums.append((line_num, previous_line_num, out_of_order))
    elif custom_include_pattern.match(line):
      if state != CUSTOM_INCLUDES:
        state = CUSTOM_INCLUDES
      elif previous_line and previous_line > line:
        problem_linenums.append((line_num, previous_line_num, out_of_order))
    else:
      problem_linenums.append((line_num, previous_line_num,
          "Unknown include type"))
    previous_line = line
    previous_line_num = line_num

  warnings = []
  for (line_num, previous_line_num, failure_type) in problem_linenums:
    if line_num in changed_linenums or previous_line_num in changed_linenums:
      warnings.append('    %s:%d:%s' % (file_path, line_num, failure_type))
  return warnings


def _CheckIncludeOrderInFile(input_api, f, changed_linenums):
  """Checks the #include order for the given file f."""

  system_include_pattern = input_api.re.compile(r'\s*#include \<.*')
  # Exclude the following includes from the check:
  # 1) #include <.../...>, e.g., <sys/...> includes often need to appear in a
  # specific order.
  # 2) <atlbase.h>, "build/build_config.h"
  excluded_include_pattern = input_api.re.compile(
      r'\s*#include (\<.*/.*|\<atlbase\.h\>|"build/build_config.h")')
  custom_include_pattern = input_api.re.compile(r'\s*#include "(?P<FILE>.*)"')
  # Match the final or penultimate token if it is xxxtest so we can ignore it
  # when considering the special first include.
  test_file_tag_pattern = input_api.re.compile(
    r'_[a-z]+test(?=(_[a-zA-Z0-9]+)?\.)')
  if_pattern = input_api.re.compile(
      r'\s*#\s*(if|elif|else|endif|define|undef).*')
  # Some files need specialized order of includes; exclude such files from this
  # check.
  uncheckable_includes_pattern = input_api.re.compile(
      r'\s*#include '
      '("ipc/.*macros\.h"|<windows\.h>|".*gl.*autogen.h")\s*')

  contents = f.NewContents()
  warnings = []
  line_num = 0

  # Handle the special first include. If the first include file is
  # some/path/file.h, the corresponding including file can be some/path/file.cc,
  # some/other/path/file.cc, some/path/file_platform.cc, some/path/file-suffix.h
  # etc. It's also possible that no special first include exists.
  # If the included file is some/path/file_platform.h the including file could
  # also be some/path/file_xxxtest_platform.h.
  including_file_base_name = test_file_tag_pattern.sub(
    '', input_api.os_path.basename(f.LocalPath()))

  for line in contents:
    line_num += 1
    if system_include_pattern.match(line):
      # No special first include -> process the line again along with normal
      # includes.
      line_num -= 1
      break
    match = custom_include_pattern.match(line)
    if match:
      match_dict = match.groupdict()
      header_basename = test_file_tag_pattern.sub(
        '', input_api.os_path.basename(match_dict['FILE'])).replace('.h', '')

      if header_basename not in including_file_base_name:
        # No special first include -> process the line again along with normal
        # includes.
        line_num -= 1
      break

  # Split into scopes: Each region between #if and #endif is its own scope.
  scopes = []
  current_scope = []
  for line in contents[line_num:]:
    line_num += 1
    if uncheckable_includes_pattern.match(line):
      continue
    if if_pattern.match(line):
      scopes.append(current_scope)
      current_scope = []
    elif ((system_include_pattern.match(line) or
           custom_include_pattern.match(line)) and
          not excluded_include_pattern.match(line)):
      current_scope.append((line_num, line))
  scopes.append(current_scope)

  for scope in scopes:
    warnings.extend(_CheckIncludeOrderForScope(scope, input_api, f.LocalPath(),
                                               changed_linenums))
  return warnings


def _CheckIncludeOrder(input_api, output_api):
  """Checks that the #include order is correct.

  1. The corresponding header for source files.
  2. C system files in alphabetical order
  3. C++ system files in alphabetical order
  4. Project's .h files in alphabetical order

  Each region separated by #if, #elif, #else, #endif, #define and #undef follows
  these rules separately.
  """
  def FileFilterIncludeOrder(affected_file):
    black_list = (input_api.DEFAULT_BLACK_LIST)
    return input_api.FilterSourceFile(affected_file, black_list=black_list)

  warnings = []
  for f in input_api.AffectedFiles(file_filter=FileFilterIncludeOrder):
    if f.LocalPath().endswith(('.cc', '.cpp', '.h', '.mm')):
      changed_linenums = set(line_num for line_num, _ in f.ChangedContents())
      warnings.extend(_CheckIncludeOrderInFile(input_api, f, changed_linenums))

  results = []
  if warnings:
    results.append(output_api.PresubmitPromptOrNotify(_INCLUDE_ORDER_WARNING,
                                                      warnings))
  return results

def _CheckTestDuplicates(input_api, output_api):
  """Checks that pixel and javascript tests don't contain duplicates.
  We use .in and .pdf files, having both can cause race conditions on the bots,
  which run the tests in parallel.
  """
  tests_added = []
  results = []
  for f in input_api.AffectedFiles():
    if f.Action() == 'D':
      continue
    if not f.LocalPath().startswith(('testing/resources/pixel/',
        'testing/resources/javascript/')):
      continue
    end_len = 0
    if f.LocalPath().endswith('.in'):
      end_len = 3
    elif f.LocalPath().endswith('.pdf'):
      end_len = 4
    else:
      continue
    path = f.LocalPath()[:-end_len]
    if path in tests_added:
      results.append(output_api.PresubmitError(
          'Remove %s to prevent shadowing %s' % (path + '.pdf',
            path + '.in')))
    else:
      tests_added.append(path)
  return results

def _CheckPNGFormat(input_api, output_api):
  """Checks that .png files have a format that will be considered valid by our
  test runners. If a file ends with .png, then it must be of the form
  NAME_expected(_(skia|skiapaths))?(_(win|mac|linux))?.pdf.#.png"""
  expected_pattern = input_api.re.compile(
      r'.+_expected(_(skia|skiapaths))?(_(win|mac|linux))?\.pdf\.\d+.png')
  results = []
  for f in input_api.AffectedFiles(include_deletes=False):
    if not f.LocalPath().endswith('.png'):
      continue
    if expected_pattern.match(f.LocalPath()):
      continue
    results.append(output_api.PresubmitError(
        'PNG file %s does not have the correct format' % f.LocalPath()))
  return results


def _CheckNoDISABLETypoInTests(input_api, output_api):
  """Checks to prevent attempts to disable tests with DISABLE_ prefix.

  This test warns if somebody tries to disable a test with the DISABLE_ prefix
  instead of DISABLED_. To filter false positives, reports are only generated
  if a corresponding MAYBE_ line exists.
  """
  problems = []

  # The following two patterns are looked for in tandem - is a test labeled
  # as MAYBE_ followed by a DISABLE_ (instead of the correct DISABLED)
  maybe_pattern = input_api.re.compile(r'MAYBE_([a-zA-Z0-9_]+)')
  disable_pattern = input_api.re.compile(r'DISABLE_([a-zA-Z0-9_]+)')

  # This is for the case that a test is disabled on all platforms.
  full_disable_pattern = input_api.re.compile(
      r'^\s*TEST[^(]*\([a-zA-Z0-9_]+,\s*DISABLE_[a-zA-Z0-9_]+\)',
      input_api.re.MULTILINE)

  for f in input_api.AffectedFiles(False):
    if not 'test' in f.LocalPath() or not f.LocalPath().endswith('.cc'):
      continue

    # Search for MABYE_, DISABLE_ pairs.
    disable_lines = {}  # Maps of test name to line number.
    maybe_lines = {}
    for line_num, line in f.ChangedContents():
      disable_match = disable_pattern.search(line)
      if disable_match:
        disable_lines[disable_match.group(1)] = line_num
      maybe_match = maybe_pattern.search(line)
      if maybe_match:
        maybe_lines[maybe_match.group(1)] = line_num

    # Search for DISABLE_ occurrences within a TEST() macro.
    disable_tests = set(disable_lines.keys())
    maybe_tests = set(maybe_lines.keys())
    for test in disable_tests.intersection(maybe_tests):
      problems.append('    %s:%d' % (f.LocalPath(), disable_lines[test]))

    contents = input_api.ReadFile(f)
    full_disable_match = full_disable_pattern.search(contents)
    if full_disable_match:
      problems.append('    %s' % f.LocalPath())

  if not problems:
    return []
  return [
      output_api.PresubmitPromptWarning(
          'Attempt to disable a test with DISABLE_ instead of DISABLED_?\n' +
          '\n'.join(problems))
  ]


def _CheckDCHECK_IS_ONHasBraces(input_api, output_api):
  """Checks to make sure DCHECK_IS_ON() does not skip the parentheses."""
  errors = []
  pattern = input_api.re.compile(r'DCHECK_IS_ON\b(?!\(\))',
                                 input_api.re.MULTILINE)
  for f in input_api.AffectedSourceFiles(input_api.FilterSourceFile):
    if (not f.LocalPath().endswith(('.cc', '.cpp', '.mm', '.h', '.inc'))):
      continue
    for lnum, line in f.ChangedContents():
      if input_api.re.search(pattern, line):
        errors.append(
            output_api.PresubmitError(
                ('%s:%d: Use of DCHECK_IS_ON() must be written as "#if ' +
                 'DCHECK_IS_ON()", not forgetting the parentheses.') %
                (f.LocalPath(), lnum)))
  return errors


def _CheckNoTrinaryTrueFalse(input_api, output_api):
  """Checks to make sure we don't introduce use of foo ? true : false."""
  problems = []
  pattern = input_api.re.compile(r'\?\s*(true|false)\s*:\s*(true|false)')
  for f in input_api.AffectedFiles():
    if not f.LocalPath().endswith(('.cc', '.cpp', '.mm', '.h', '.inc')):
      continue

    for line_num, line in f.ChangedContents():
      if pattern.match(line):
        problems.append('    %s:%d' % (f.LocalPath(), line_num))

  if not problems:
    return []
  return [
      output_api.PresubmitPromptWarning(
          'Please consider avoiding the "? true : false" pattern if possible.\n'
          + '\n'.join(problems))
  ]


def _CheckNoPragmaOnce(input_api, output_api):
  """Make sure that banned functions are not used."""
  files = []
  pattern = input_api.re.compile(r'^#pragma\s+once', input_api.re.MULTILINE)
  for f in input_api.AffectedSourceFiles(input_api.FilterSourceFile):
    if not f.LocalPath().endswith('.h'):
      continue
    contents = input_api.ReadFile(f)
    if pattern.search(contents):
      files.append(f)

  if files:
    return [
        output_api.PresubmitError(
            'Do not use #pragma once in header files.\n'
            'See http://www.chromium.org/developers/coding-style#TOC-File-headers',
            files)
    ]
  return []


def _CheckForCcOrCppIncludes(input_api, output_api):
  """Check that nobody tries to include a cc or cpp file. It's a relatively
  common error which results in duplicate symbols in object
  files. This may not always break the build until someone later gets
  very confusing linking errors."""
  results = []
  for f in input_api.AffectedFiles(include_deletes=False):
    # We let third_party code do whatever it wants
    if (f.LocalPath().startswith('third_party') and
        not f.LocalPath().startswith('third_party/blink') and
        not f.LocalPath().startswith('third_party\\blink')):
      continue

    if not f.LocalPath().endswith(('.cc', '.cpp', '.mm', '.m', '.h')):
      continue

    for _, line in f.ChangedContents():
      if line.startswith('#include "'):
        included_file = line.split('"')[1]
        if _IsCPlusPlusFile(input_api, included_file):
          # The most common naming for external files with C++ code,
          # apart from standard headers, is to call them foo.inc, but
          # Chromium sometimes uses foo-inc.cc so allow that as well.
          if not included_file.endswith(('.h', '-inc.cc')):
            results.append(
                output_api.PresubmitError(
                    'Only header files or .inc files should be included in other\n'
                    'C++ files. Compiling the contents of a cc or cpp file more than\n'
                    'once will cause duplicate information in the build which may\n'
                    'later result in strange link_errors.\n' + f.LocalPath() +
                    ':\n    ' + line))

  return results


def CheckChangeOnUpload(input_api, output_api):
  cpp_source_filter = lambda x: input_api.FilterSourceFile(
      x, white_list=(r'\.(?:c|cc|cpp|h)$',))

  results = []
  results.extend(_CheckUnwantedDependencies(input_api, output_api))
  results.extend(
      input_api.canned_checks.CheckPatchFormatted(input_api, output_api))
  results.extend(
      input_api.canned_checks.CheckChangeLintsClean(input_api, output_api,
                                                    cpp_source_filter,
                                                    LINT_FILTERS))
  results.extend(_CheckIncludeOrder(input_api, output_api))
  results.extend(_CheckTestDuplicates(input_api, output_api))
  results.extend(_CheckPNGFormat(input_api, output_api))
  results.extend(_CheckNoDISABLETypoInTests(input_api, output_api))
  results.extend(_CheckDCHECK_IS_ONHasBraces(input_api, output_api))
  results.extend(_CheckNoTrinaryTrueFalse(input_api, output_api))
  results.extend(_CheckNoPragmaOnce(input_api, output_api))
  results.extend(_CheckForCcOrCppIncludes(input_api, output_api))

  author = input_api.change.author_email
  if author and author not in _KNOWN_ROBOTS:
    results.extend(
        input_api.canned_checks.CheckAuthorizedAuthor(input_api, output_api))

  for f in input_api.AffectedFiles():
    path, name = input_api.os_path.split(f.LocalPath())
    if name == 'PRESUBMIT.py':
      full_path = input_api.os_path.join(input_api.PresubmitLocalPath(), path)
      test_file = input_api.os_path.join(path, 'PRESUBMIT_test.py')
      if f.Action() != 'D' and input_api.os_path.exists(test_file):
        # The PRESUBMIT.py file (and the directory containing it) might
        # have been affected by being moved or removed, so only try to
        # run the tests if they still exist.
        results.extend(
            input_api.canned_checks.RunUnitTestsInDirectory(
                input_api,
                output_api,
                full_path,
                whitelist=[r'^PRESUBMIT_test\.py$']))

  return results
