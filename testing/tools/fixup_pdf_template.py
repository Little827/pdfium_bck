#!/usr/bin/env python
# Copyright 2014 The PDFium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Expands a hand-written PDF testcase (template) into a valid PDF file.

There are several places in a PDF file where byte-offsets are required. This
script replaces {{name}}-style variables in the input with calculated results

  {{header}} - expands to the header comment required for PDF files.
  {{xref}} - expands to a generated xref table, noting the offset.
  {{trailer}} - expands to a standard trailer with "1 0 R" as the /Root.
  {{startxref} - expands to a startxref directive followed by correct offset.
  {{object x y}} - expands to |x y obj| declaration, noting the offset.
  {{streamlen}} - expands to |/Length n|.
  {{xfapreamble x y}} - expands to an object |x y obj| containing a XML preamble
                        to be used in XFA docs.
  {{xfaconfig x y}} - expands to an object |x y obj| containing a config XML
                      block to be used in XFA docs.
  {{xfalocale x y}} - expands to an object |x y obj| containing a locale XML
                      block to be used in XFA docs.
  {{xfapostamble x y}} - expands to an object |x y obj| containing a XML
                         posteamble to be used in XFA docs.
  {{embedroboto x}} - expands to a set of objects (x, 0), (x+1, 0), and (x+2, 0)
                      that contain an embedded version of the Roboto-Regular
                      font.
"""

import cStringIO
import optparse
import os
import re
import sys

SCRIPT_PATH = os.path.abspath(os.path.dirname(__file__))

class StreamLenState:
  START = 1
  FIND_STREAM = 2
  FIND_ENDSTREAM = 3

class TemplateProcessor:
  HEADER_TOKEN = '{{header}}'
  HEADER_REPLACEMENT = '%PDF-1.7\n%\xa0\xf2\xa4\xf4'

  XREF_TOKEN = '{{xref}}'
  XREF_REPLACEMENT = 'xref\n%d %d\n'

  XREF_REPLACEMENT_N = '%010d %05d n \n'
  XREF_REPLACEMENT_F = '0000000000 65535 f \n'
  # XREF rows must be exactly 20 bytes - space required.
  assert(len(XREF_REPLACEMENT_F) == 20)

  TRAILER_TOKEN = '{{trailer}}'
  TRAILER_REPLACEMENT = 'trailer<< /Root 1 0 R /Size %d >>'

  STARTXREF_TOKEN = '{{startxref}}'
  STARTXREF_REPLACEMENT = 'startxref\n%d'

  OBJECT_PATTERN = r'\{\{object\s+(\d+)\s+(\d+)\}\}'
  OBJECT_REPLACEMENT = r'\1 \2 obj'

  STREAMLEN_TOKEN = '{{streamlen}}'
  STREAMLEN_REPLACEMENT = '/Length %d'

  XFAPREAMBLE_PATTERN = r'\{\{xfapreamble\s+(\d+)\s+(\d+)\}\}'
  XFAPREAMBLE_REPLACEMENT = '%d %d obj\n<<\n  /Length %d\n>>\nstream\n%s\nendstream\nendobj\n'
  XFAPREAMBLE_STREAM = '<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/" timeStamp="2018-02-23T21:37:11Z" uuid="21482798-7bf0-40a4-bc5d-3cefdccf32b5">'

  XFAPOSTAMBLE_PATTERN = r'\{\{xfapostamble\s+(\d+)\s+(\d+)\}\}'
  XFAPOSTAMBLE_REPLACEMENT = '%d %d obj\n<<\n  /Length %d\n>>\nstream\n%s\nendstream\nendobj\n'
  XFAPOSTAMBLE_STREAM = '</xdp:xdp>'

  XFACONFIG_PATTERN = r'\{\{xfaconfig\s+(\d+)\s+(\d+)\}\}'
  XFACONFIG_REPLACEMENT = '%d %d obj\n<<\n  /Length %d\n>>\nstream\n%s\nendstream\nendobj\n'
  XFACONFIG_STREAM = '''<config xmlns="http://www.xfa.org/schema/xci/3.0/">
  <agent name="designer">
    <destination>pdf</destination>
    <pdf>
      <fontInfo/>
    </pdf>
  </agent>
  <present>
    <pdf>
      <version>1.7</version>
      <adobeExtensionLevel>8</adobeExtensionLevel>
      <renderPolicy>client</renderPolicy>
      <scriptModel>XFA</scriptModel>
      <interactive>1</interactive>
    </pdf>
    <xdp>
      <packets>*</packets>
    </xdp>
    <destination>pdf</destination>
    <script>
      <runScripts>server</runScripts>
    </script>
  </present>
  <acrobat>
    <acrobat7>
      <dynamicRender>required</dynamicRender>
    </acrobat7>
    <validate>preSubmit</validate>
  </acrobat>
</config>'''

  XFALOCALE_PATTERN = r'\{\{xfalocale\s+(\d+)\s+(\d+)\}\}'
  XFALOCALE_REPLACEMENT = '%d %d obj\n<<\n  /Length %d\n>>\nstream\n%s\nendstream\nendobj\n'
  XFALOCALE_STREAM = '''<localeSet xmlns="http://www.xfa.org/schema/xfa-locale-set/2.7/">
  <locale name="en_US" desc="English (United States)">
    <calendarSymbols name="gregorian">
      <monthNames>
        <month>January</month>
        <month>February</month>
        <month>March</month>
        <month>April</month>
        <month>May</month>
        <month>June</month>
        <month>July</month>
        <month>August</month>
        <month>September</month>
        <month>October</month>
        <month>November</month>
        <month>December</month>
      </monthNames>
      <monthNames abbr="1">
        <month>Jan</month>
        <month>Feb</month>
        <month>Mar</month>
        <month>Apr</month>
        <month>May</month>
        <month>Jun</month>
        <month>Jul</month>
        <month>Aug</month>
        <month>Sep</month>
        <month>Oct</month>
        <month>Nov</month>
        <month>Dec</month>
      </monthNames>
      <dayNames>
        <day>Sunday</day>
        <day>Monday</day>
        <day>Tuesday</day>
        <day>Wednesday</day>
        <day>Thursday</day>
        <day>Friday</day>
        <day>Saturday</day>
      </dayNames>
      <dayNames abbr="1">
        <day>Sun</day>
        <day>Mon</day>
        <day>Tue</day>
        <day>Wed</day>
        <day>Thu</day>
        <day>Fri</day>
        <day>Sat</day>
      </dayNames>
      <meridiemNames>
        <meridiem>AM</meridiem>
        <meridiem>PM</meridiem>
      </meridiemNames>
      <eraNames>
        <era>BC</era>
        <era>AD</era>
      </eraNames>
    </calendarSymbols>
    <datePatterns>
      <datePattern name="full">EEEE, MMMM D, YYYY</datePattern>
      <datePattern name="long">MMMM D, YYYY</datePattern>
      <datePattern name="med">MMM D, YYYY</datePattern>
      <datePattern name="short">M/D/YY</datePattern>
    </datePatterns>
    <timePatterns>
      <timePattern name="full">h:MM:SS A Z</timePattern>
      <timePattern name="long">h:MM:SS A Z</timePattern>
      <timePattern name="med">h:MM:SS A</timePattern>
      <timePattern name="short">h:MM A</timePattern>
    </timePatterns>
    <dateTimeSymbols>GyMdkHmsSEDFwWahKzZ</dateTimeSymbols>
    <numberPatterns>
      <numberPattern name="numeric">z,zz9.zzz</numberPattern>
      <numberPattern name="currency">$z,zz9.99|($z,zz9.99)</numberPattern>
      <numberPattern name="percent">z,zz9%</numberPattern>
    </numberPatterns>
    <numberSymbols>
      <numberSymbol name="decimal">.</numberSymbol>
      <numberSymbol name="grouping">,</numberSymbol>
      <numberSymbol name="percent">%</numberSymbol>
      <numberSymbol name="minus">-</numberSymbol>
      <numberSymbol name="zero">0</numberSymbol>
    </numberSymbols>
    <currencySymbols>
      <currencySymbol name="symbol">$</currencySymbol>
      <currencySymbol name="isoname">USD</currencySymbol>
      <currencySymbol name="decimal">.</currencySymbol>
    </currencySymbols>
    <typefaces>
      <typeface name="Myriad Pro"/>
      <typeface name="Minion Pro"/>
      <typeface name="Courier Std"/>
      <typeface name="Adobe Pi Std"/>
      <typeface name="Adobe Hebrew"/>
      <typeface name="Adobe Arabic"/>
      <typeface name="Adobe Thai"/>
      <typeface name="Kozuka Gothic Pro-VI M"/>
      <typeface name="Kozuka Mincho Pro-VI R"/>
      <typeface name="Adobe Ming Std L"/>
      <typeface name="Adobe Song Std L"/>
      <typeface name="Adobe Myungjo Std M"/>
    </typefaces>
  </locale>
</localeSet>'''

  EMBED_ROBOTO_PATTERN = r'\{\{embedroboto\s+(\d+)\}\}'

  ROBOTO_SPECIFICATION_BLOB = \
'''%d 0 obj
<<
  /BaseFont /Roboto
  /FirstChar 0
  /FontDescriptor %d 0 R
  /LastChar 255
  /Name /Roboto
  /Subtype /TrueType
  /Type /Font
  /Widths [
    443 443 443 443 443 443 443 443 443 443 443 443 443 443 443 443
    443 443 443 443 443 443 443 443 443 443 443 443 443 443 443 443
    248 257 320 616 562 732 622 174 342 348 431 567 196 276 263 412
    562 562 562 562 562 562 562 562 562 562 242 211 508 549 522 472
    898 652 623 651 656 568 553 681 713 272 552 627 538 873 713 688
    631 688 616 593 597 648 636 887 627 601 599 265 410 265 418 451
    309 544 561 523 564 530 347 561 551 243 239 507 243 876 552 570
    561 568 338 516 327 551 484 751 496 473 496 338 244 338 680 443
    652 652 651 568 713 688 648 544 544 544 544 544 544 523 530 530
    530 530 247 247 247 247 552 570 570 570 570 570 551 551 551 551
    551 374 547 581 613 337 489 595 786 786 625 313 418 443 935 688
    443 534 443 443 525 566 443 443 443 443 443 447 455 443 844 566
    473 244 554 443 340 443 443 469 469 669 443 652 652 688 954 908
    656 781 354 357 200 200 571 443 473 601 455 562 300 300 554 568
    570 261 199 344 958 652 568 652 568 568 272 272 272 272 688 688
    443 688 648 648 648 247 471 472 458 427 243 334 248 373 271 444
  ]
>>
endobj
'''

  ROBOTO_DESCRIPTOR_BLOB = \
'''%d 0 obj
<<
  /Ascent 1056
  /CapHeight 711
  /Descent -271
  /Flags 32
  /FontBBox [
    -891
    -271
    2045
    1056
  ]
  /FontFamily (Roboto)
  /FontFile2 %d 0 R
  /FontName /Roboto
  /FontStretch /Normal
  /FontWeight 400
  /ItalicAngle 0
  /StemV 92
  /Type /FontDescriptor
  /XHeight 528
>>
endobj
'''

  ROBOTO_FONT_FILE = 'Roboto-Regular.ttf'
  ROBOTO_FONT_BLOB = 'stream\n%s\nendstream'
  ROBOTO_STREAM_BLOB = \
'''%d 0 obj
<<
  /Length1 %d
  /Length %d
>>
%s
endobj
'''


  def __init__(self):
    self.streamlen_state = StreamLenState.START
    self.streamlens = []
    self.offset = 0
    self.xref_offset = 0
    self.max_object_number = 0
    self.objects = {}
    roboto_font_path = os.path.join(SCRIPT_PATH, self.ROBOTO_FONT_FILE)
    roboto_font_binary = None
    try:
      with open(roboto_font_path, 'rb') as f:
        roboto_font_binary = f.read()
    except IOError:
      print >> sys.stderr, 'failed to process %s' % roboto_font_path
    self.roboto_font_stream = self.ROBOTO_FONT_BLOB % roboto_font_binary

  def insert_xref_entry(self, object_number, generation_number):
    self.insert_delta_xref_entry(object_number, generation_number, 0)

  def insert_delta_xref_entry(self, object_number, generation_number, delta):
    self.objects[object_number] = (self.offset + delta, generation_number)
    self.max_object_number = max(self.max_object_number, object_number)

  def insert_font_obj(self, line, delta, object_number, object_str):
    self.insert_xref_entry(object_number, 0)
    line += object_str
    delta += len(object_str)
    return line, delta

  def generate_xref_table(self):
    result = self.XREF_REPLACEMENT % (0, self.max_object_number + 1)
    for i in range(0, self.max_object_number + 1):
      if i in self.objects:
        result += self.XREF_REPLACEMENT_N % self.objects[i]
      else:
        result += self.XREF_REPLACEMENT_F
    return result

  def preprocess_line(self, line):
    if self.STREAMLEN_TOKEN in line:
      assert(self.streamlen_state == StreamLenState.START)
      self.streamlen_state = StreamLenState.FIND_STREAM
      self.streamlens.append(0)
      return

    if (self.streamlen_state == StreamLenState.FIND_STREAM and
        line.rstrip() == 'stream'):
      self.streamlen_state = StreamLenState.FIND_ENDSTREAM
      return

    if self.streamlen_state == StreamLenState.FIND_ENDSTREAM:
      if line.rstrip() == 'endstream':
        self.streamlen_state = StreamLenState.START
      else:
        self.streamlens[-1] += len(line)

  def process_line(self, line):
    if self.HEADER_TOKEN in line:
      line = line.replace(self.HEADER_TOKEN, self.HEADER_REPLACEMENT)
    if self.STREAMLEN_TOKEN in line:
      sub = self.STREAMLEN_REPLACEMENT % self.streamlens.pop(0)
      line = re.sub(self.STREAMLEN_TOKEN, sub, line)
    if self.XREF_TOKEN in line:
      self.xref_offset = self.offset
      line = self.generate_xref_table()
    if self.TRAILER_TOKEN in line:
      replacement = self.TRAILER_REPLACEMENT % (self.max_object_number + 1)
      line = line.replace(self.TRAILER_TOKEN, replacement)
    if self.STARTXREF_TOKEN in line:
      replacement = self.STARTXREF_REPLACEMENT % self.xref_offset
      line = line.replace(self.STARTXREF_TOKEN, replacement)
    match = re.match(self.OBJECT_PATTERN, line)
    if match:
      self.insert_xref_entry(int(match.group(1)), int(match.group(2)))
      line = re.sub(self.OBJECT_PATTERN, self.OBJECT_REPLACEMENT, line)
    line = self.replace_xfa_tag(line,
                                self.XFAPREAMBLE_PATTERN,
                                self.XFAPREAMBLE_REPLACEMENT,
                                self.XFAPREAMBLE_STREAM)
    line = self.replace_xfa_tag(line,
                                self.XFACONFIG_PATTERN,
                                self.XFACONFIG_REPLACEMENT,
                                self.XFACONFIG_STREAM)
    line = self.replace_xfa_tag(line,
                                self.XFALOCALE_PATTERN,
                                self.XFALOCALE_REPLACEMENT,
                                self.XFALOCALE_STREAM)
    line = self.replace_xfa_tag(line,
                                self.XFAPOSTAMBLE_PATTERN,
                                self.XFAPOSTAMBLE_REPLACEMENT,
                                self.XFAPOSTAMBLE_STREAM)

    match = re.match(self.EMBED_ROBOTO_PATTERN, line)
    if match:
      line = self.replace_embed_roboto_tag(int(match.group(1)))

    self.offset += len(line)
    return line

  def replace_xfa_tag(self, line, pattern, replacement, stream):
    match = re.match(pattern, line)
    if match:
      x = int(match.group(1))
      y = int(match.group(2))
      self.insert_xref_entry(x, y)
      line = replacement % (x, y, len(stream), stream)
    return line

  def replace_embed_roboto_tag(self, x):
    descriptor_x = x + 1
    stream_x = x + 2
    line = ""
    delta = 0
    specification_str = self.ROBOTO_SPECIFICATION_BLOB % (x, descriptor_x)
    (line, delta) = self.insert_font_obj(line, delta, x, specification_str)
    descriptor_str = self.ROBOTO_DESCRIPTOR_BLOB % (descriptor_x, stream_x)
    (line, delta) = self.insert_font_obj(line, delta, descriptor_x,
                                         descriptor_str)
    stream_str = self.ROBOTO_STREAM_BLOB % (stream_x,
                                            len(self.roboto_font_stream),
                                            len(self.roboto_font_stream),
                                            self.roboto_font_stream)
    (line, delta) = self.insert_font_obj(line, delta, stream_x, stream_str)
    return line


def expand_file(input_path, output_path):
  processor = TemplateProcessor()
  try:
    with open(input_path, 'rb') as infile:
      with open(output_path, 'wb') as outfile:
        preprocessed = cStringIO.StringIO()
        for line in infile:
          preprocessed.write(line)
          processor.preprocess_line(line)
        preprocessed.seek(0)
        for line in preprocessed:
          outfile.write(processor.process_line(line))
  except IOError:
    print >> sys.stderr, 'failed to process %s' % input_path


def main():
  parser = optparse.OptionParser()
  parser.add_option('--output-dir', default='')
  options, args = parser.parse_args()
  for testcase_path in args:
    testcase_filename = os.path.basename(testcase_path)
    testcase_root, _ = os.path.splitext(testcase_filename)
    output_dir = os.path.dirname(testcase_path)
    if options.output_dir:
      output_dir = options.output_dir
    output_path = os.path.join(output_dir, testcase_root + '.pdf')
    expand_file(testcase_path, output_path)
  return 0


if __name__ == '__main__':
  sys.exit(main())
