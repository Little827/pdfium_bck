#!/usr/bin/env python3
# Copyright 2019 The PDFium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Encodes binary data using one or more PDF stream filters.

This tool helps with the common task of converting binary data into ASCII PDF
streams. In test PDFs (and the corresponding .in files), we often want the
contents to be plain (or mostly plain) ASCII.

Requires Python 3 (mainly for Ascii85 support). This should be fine for a
manually-run script.
"""

import argparse
import base64
import collections
import collections.abc
import io
import struct
import sys
import zlib


class _FilterSettings:

  def __init__(self):
    self.entries = collections.OrderedDict()
    self.filter_names = []
    self.decode_parms = []

  def SetEntry(self, key, value):
    assert key != '/Filter' and key != '/DecodeParms'
    self.entries[key] = value

  def AddFilter(self, name, decode_parms=None):
    self.filter_names.append(name)
    self.decode_parms.append(decode_parms)

  def GetEntries(self):
    entries = self.entries.copy()

    if len(self.filter_names) == 1:
      entries['/Filter'] = self.filter_names[0]
    elif len(self.filter_names) > 1:
      entries['/Filter'] = self.filter_names

    if any(item is not None for item in self.decode_parms):
      if len(self.decode_parms) == 1:
        entries['/DecodeParms'] = self.decode_parms[0]
      else:
        entries['/DecodeParms'] = self.decode_parms

    return entries


class _PdfStream:
  _unique_filter_classes = []
  _filter_classes = {}

  @staticmethod
  def GetFilterByName(name):
    # Tolerate any case-insensitive match for "/Name" or "Name", or an alias.
    key_name = name.lower()
    if key_name and key_name[0] == '/':
      key_name = key_name[:1]

    filter_class = _PdfStream._filter_classes.get(key_name)
    if not filter_class:
      raise KeyError(name)

    return filter_class

  @classmethod
  def Register(cls):
    assert cls not in _PdfStream._unique_filter_classes
    _PdfStream._unique_filter_classes.append(cls)
    cls.RegisterByName()
    cls.RegisterByAliases()

  @classmethod
  def RegisterByName(cls):
    assert cls.name[0] == '/'
    lower_name = cls.name.lower()
    _PdfStream._filter_classes[lower_name] = cls
    _PdfStream._filter_classes[lower_name[1:]] = cls

  @classmethod
  def RegisterByAliases(cls):
    for alias in cls.aliases:
      _PdfStream._filter_classes[alias.lower()] = cls

  @staticmethod
  def GetHelp():
    text = 'Available filters:\n'
    for filter_class in _PdfStream._unique_filter_classes:
      text += '  {} (aliases: {})\n'.format(filter_class.name,
                                            ', '.join(filter_class.aliases))
    return text

  def __init__(self, filter_settings, out_buffer, **kwargs):
    del kwargs
    self.filter_settings = filter_settings
    self.buffer = out_buffer

  def write(self, data):
    self.buffer.write(data)

  def flush(self):
    self.buffer.flush()

  def close(self):
    self.buffer.close()
    self.AddEntries()

  def AddEntries(self):
    self.filter_settings.AddFilter(self.name)


class _SinkPdfStream(_PdfStream):

  def __init__(self, filter_settings):
    super().__init__(filter_settings, io.BytesIO())

  def close(self):
    # Don't call io.BytesIO.close(); this deallocates the written data.
    self.flush()

  def getbuffer(self):
    return self.buffer.getbuffer()


class _AsciiPdfStream(_PdfStream):

  def __init__(self, filter_settings, out_buffer, wrapcol=0, **kwargs):
    super().__init__(filter_settings, out_buffer, **kwargs)
    self.wrapcol = wrapcol
    self.column = 0

  def write(self, data):
    if not self.wrapcol:
      self.buffer.write(data)
      return

    tail = self.wrapcol - self.column
    self.buffer.write(data[:tail])
    if tail >= len(data):
      self.column += len(data)
      return

    for start in range(tail, len(data), self.wrapcol):
      self.buffer.write(b'\n')
      self.buffer.write(data[start:start + self.wrapcol])

    tail = len(data) - tail
    self.column = self.wrapcol - -tail % self.wrapcol


class _Ascii85DecodePdfStream(_AsciiPdfStream):
  name = '/ASCII85Decode'
  aliases = ('ascii85', 'base85')

  def __init__(self, filter_settings, out_buffer, **kwargs):
    super().__init__(filter_settings, out_buffer, **kwargs)
    self.trailer = b''

  def write(self, data):
    # Need to write ASCII85 in units of 4.
    data = self.trailer + data
    trailer_length = len(data) % 4
    super().write(base64.a85encode(data[:-trailer_length]))
    self.trailer = data[-trailer_length:]

  def close(self):
    super().write(base64.a85encode(self.trailer))
    # Avoid breaking the end-of-data marker (but still try to wrap).
    if self.wrapcol and self.column > self.wrapcol - 2:
      self.buffer.write(b'\n')
    self.buffer.write(b'~>')
    super().close()


class _AsciiHexDecodePdfStream(_AsciiPdfStream):
  name = '/ASCIIHexDecode'
  aliases = ('base16', 'hex', 'hexadecimal')

  def __init__(self, filter_settings, out_buffer, **kwargs):
    super().__init__(filter_settings, out_buffer, **kwargs)

  def write(self, data):
    super().write(base64.b16encode(data))


class _FlateDecodePdfStream(_PdfStream):
  name = '/FlateDecode'
  aliases = ('deflate', 'flate', 'zlib')

  def __init__(self, filter_settings, out_buffer, **kwargs):
    super().__init__(filter_settings, out_buffer, **kwargs)
    self.deflate = zlib.compressobj(level=9, memLevel=9)

  def write(self, data):
    self.buffer.write(self.deflate.compress(data))

  def flush(self):
    self.buffer.write(self.deflate.flush(zlib.Z_NO_FLUSH))

  def close(self):
    self.buffer.write(self.deflate.flush())
    super().close()


class _VirtualPdfStream(_PdfStream):

  @classmethod
  def RegisterByName(cls):
    pass

  def AddEntries(self):
    pass


class _PassthroughPdfStream(_VirtualPdfStream):
  name = '(virtual) passthrough'
  aliases = ('noop', 'passthrough')


class _PngIdatPdfStream(_VirtualPdfStream):
  name = '(virtual) PNG IDAT'
  aliases = ('png',)

  _EXPECT_HEADER = -1
  _EXPECT_LENGTH = -2
  _EXPECT_CHUNK_TYPE = -3
  _EXPECT_CRC = -4

  _PNG_HEADER = int.from_bytes(bytes((137, 80, 78, 71, 13, 10, 26, 10)), 'big')
  _PNG_CHUNK_IHDR = int.from_bytes(b'IHDR', 'big')
  _PNG_CHUNK_IDAT = int.from_bytes(b'IDAT', 'big')

  def __init__(self, filter_settings, out_buffer, **kwargs):
    super().__init__(filter_settings, out_buffer, **kwargs)
    self.chunk = _PngIdatPdfStream._EXPECT_HEADER
    self.chunk_data = bytearray()
    self.remaining = 8
    self.accumulator = 0
    self.length = 0
    self.ihdr = None

  def write(self, data):
    position = 0
    while position < len(data):
      if self.chunk >= 0:
        # Read part of the chunk data.
        read_size = min(self.remaining, len(data) - position)
        read_data = data[position:position + read_size]
        if self.chunk == _PngIdatPdfStream._PNG_CHUNK_IDAT:
          self.buffer.write(read_data)
        elif self.chunk == _PngIdatPdfStream._PNG_CHUNK_IHDR:
          self.chunk_data.extend(read_data)
        self.remaining -= read_size
        if self.remaining == 0:
          self.ProcessChunkData()
          self.chunk_data.clear()
          self.ResetAccumulator(_PngIdatPdfStream._EXPECT_CRC, 4)
        position += read_size
      else:
        # As far as we're concerned, PNG files are just a header followed by a
        # series of (length, chunk type, data[length], CRC) chunks.
        if self.AccumulateByte(data[position]):
          if self.chunk == _PngIdatPdfStream._EXPECT_HEADER:
            if self.accumulator != _PngIdatPdfStream._PNG_HEADER:
              raise ValueError('Invalid PNG header', self.accumulator)
            self.ResetAccumulator(_PngIdatPdfStream._EXPECT_LENGTH, 4)
          elif self.chunk == _PngIdatPdfStream._EXPECT_LENGTH:
            self.length = self.accumulator
            self.ResetAccumulator(_PngIdatPdfStream._EXPECT_CHUNK_TYPE, 4)
          elif self.chunk == _PngIdatPdfStream._EXPECT_CHUNK_TYPE:
            self.ResetAccumulator(self.accumulator, self.length)
          elif self.chunk == _PngIdatPdfStream._EXPECT_CRC:
            # Don't care if the CRC is correct.
            self.ResetAccumulator(_PngIdatPdfStream._EXPECT_LENGTH, 4)
        position += 1

  def ResetAccumulator(self, chunk, remaining):
    self.chunk = chunk
    self.remaining = remaining
    self.accumulator = 0

  def AccumulateByte(self, byte):
    assert self.remaining > 0
    self.accumulator = self.accumulator << 8 | byte
    self.remaining -= 1
    return self.remaining == 0

  def ProcessChunkData(self):
    if self.chunk == _PngIdatPdfStream._PNG_CHUNK_IHDR:
      assert self.ihdr is None
      self.ihdr = struct.unpack('>IIBBBBB', self.chunk_data)

  def AddEntries(self):
    self.filter_settings.SetEntry('/Type', '/XObject')
    self.filter_settings.SetEntry('/Subtype', '/Image')

    (width, height, bit_depth, color_type, compression_method, filter_method,
     interlace_method) = self.ihdr
    assert interlace_method == 0

    self.filter_settings.SetEntry('/Width', width)
    self.filter_settings.SetEntry('/Height', height)

    if color_type == 0:
      colors = 1
      color_space = '/DeviceGray'
    elif color_type == 2:
      colors = 3
      color_space = '/DeviceRGB'
    elif color_type == 3:
      # Some manual intervention required to add the PLTE.
      colors = 1
      color_space = ['/Indexed', '/DeviceRGB', 0, '<000000>']
    elif color_type == 4:
      raise ValueError('Color type 4 (YA) not supported')
    elif color_type == 6:
      raise ValueError('Color type 6 (RGBA) not supported')
    else:
      raise ValueError('Invalid color type', color_type)
    self.filter_settings.SetEntry('/ColorSpace', color_space)

    self.filter_settings.SetEntry('/BitsPerComponent', bit_depth)

    if compression_method == 0:
      decode_parms = collections.OrderedDict()
      if filter_method == 0:
        decode_parms['/Predictor'] = 15
      else:
        raise ValueError('Invalid filter method', filter_method)
      decode_parms['/Colors'] = colors
      decode_parms['/BitsPerComponent'] = bit_depth
      decode_parms['/Columns'] = width
      self.filter_settings.AddFilter('/FlateDecode', decode_parms)
    else:
      raise ValueError('Invalid compression method', compression_method)


_Ascii85DecodePdfStream.Register()
_AsciiHexDecodePdfStream.Register()
_FlateDecodePdfStream.Register()
_PassthroughPdfStream.Register()
_PngIdatPdfStream.Register()

_DEFAULT_FILTERS = (_Ascii85DecodePdfStream, _FlateDecodePdfStream)


def _ParseCommandLine(argv):
  arg_parser = argparse.ArgumentParser(
      description='Encodes binary data using one or more PDF stream filters.',
      epilog=_PdfStream.GetHelp(),
      formatter_class=argparse.RawDescriptionHelpFormatter)
  arg_parser.add_argument(
      '-r',
      '--raw',
      action='store_true',
      help='output raw bytes (no PDF stream header or trailer)')
  arg_parser.add_argument(
      '-l',
      '--length',
      action='store_true',
      help='output actual /Length, instead of {{streamlen}}')
  arg_parser.add_argument(
      '-w',
      '--wrap',
      default=80,
      type=int,
      help='wrap ASCII lines at COLUMN; defaults to 80 (0 = off)',
      metavar='COLUMN')
  arg_parser.add_argument(
      '-f',
      '--filter',
      action='append',
      type=_PdfStream.GetFilterByName,
      help=('one or more filters, in decoding order; defaults to ' + ' '.join(
          [f.name for f in _DEFAULT_FILTERS])),
      metavar='NAME')
  arg_parser.add_argument(
      'infile',
      nargs='?',
      default=sys.stdin,
      type=argparse.FileType('r'),
      help='input file; use - for standard input (default)')
  arg_parser.add_argument(
      'outfile',
      nargs='?',
      default=sys.stdout,
      type=argparse.FileType('w'),
      help='output file; use - for standard output (default)')
  args = arg_parser.parse_intermixed_args(argv)
  args.filter = args.filter or _DEFAULT_FILTERS
  assert args.wrap >= 0, '--wrap COLUMN must be non-negative'
  return args


def _WrapWithFilters(filter_settings, out_buffer, filter_classes, **kwargs):
  for filter_class in filter_classes:
    out_buffer = filter_class(filter_settings, out_buffer, **kwargs)
  return out_buffer


def _CopyBytes(in_buffer, out_buffer):
  data = bytearray(io.DEFAULT_BUFFER_SIZE)
  while True:
    data_length = in_buffer.readinto(data)
    if not data_length:
      return
    out_buffer.write(data[:data_length])


class _PdfValuePrinter:

  def __init__(self, out_buffer):
    self.out_buffer = out_buffer
    self.indent = b''
    self.line_length = 0

  def write(self, data):
    if not self.line_length:
      self.out_buffer.write(self.indent)
      self.line_length += len(self.indent)
    self.out_buffer.write(data)
    self.line_length += len(data)

  def IncreaseIndent(self):
    self.indent = b' ' * (len(self.indent) + 2)

  def DecreaseIndent(self):
    self.indent = b' ' * (len(self.indent) - 2)

  def PrintLineBreak(self):
    if self.line_length:
      self.write(b'\n')
      self.line_length = 0

  def PrintValue(self, value):
    if isinstance(value, (str, collections.abc.ByteString)):
      self._PrintPrimitive(value)
    elif isinstance(value, collections.abc.Sequence):
      self._PrintArray(value)
    elif isinstance(value, collections.abc.Mapping):
      self._PrintDict(value)
    else:
      self._PrintPrimitive(value)

  def _PrintPrimitive(self, value):
    if value is None:
      value = b'null'
    else:
      value = str(value).encode('ascii')
    self.write(value)

  def _PrintArray(self, value):
    self.write(b'[')
    self.PrintLineBreak()
    self.IncreaseIndent()
    for item in value:
      self.PrintValue(item)
      self.PrintLineBreak()
    self.DecreaseIndent()
    self.write(b']')

  def _PrintDict(self, value):
    self.write(b'<<')
    self.PrintLineBreak()
    self.IncreaseIndent()
    for item_key, item_value in value.items():
      if item_key != '/Length' or item_value != '{{streamlen}}':
        self.PrintValue(item_key)
        self.write(b' ')
      self.PrintValue(item_value)
      self.PrintLineBreak()
    self.DecreaseIndent()
    self.write(b'>>')


def _WritePdfStreamObject(printer,
                          data,
                          entries,
                          raw=False,
                          use_streamlen=False):
  if not raw:
    entries['/Length'] = '{{streamlen}}' if use_streamlen else len(data)
    printer.PrintValue(entries)
    printer.PrintLineBreak()
    printer.write(b'stream')
    printer.PrintLineBreak()

  printer.write(data)

  if not raw:
    if data and data[-1] != '\n':
      printer.PrintLineBreak()
    printer.write(b'endstream')
    printer.PrintLineBreak()


def main(argv):
  args = _ParseCommandLine(argv)

  filter_settings = _FilterSettings()
  encoded_sink = _SinkPdfStream(filter_settings)
  with args.infile:
    out_buffer = _WrapWithFilters(
        filter_settings, encoded_sink, args.filter, wrapcol=args.wrap)
    _CopyBytes(args.infile.buffer, out_buffer)
    out_buffer.close()

  _WritePdfStreamObject(
      _PdfValuePrinter(args.outfile.buffer),
      encoded_sink.getbuffer(),
      filter_settings.GetEntries(),
      raw=args.raw,
      use_streamlen=not args.length)
  return args.outfile.close()


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
