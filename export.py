# Copyright (C) 2019 Yossi Gottlieb
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import sys, os
import argparse
import struct
import binascii
from collections import Counter

class Entry(object):
  def __init__(self, data):
    self.hdr = struct.unpack_from('BB', data, 0x0)
    if self.hdr != (0x94, 0x03):
      raise ValueError('Invalid entry')

    # Name length
    name_len = struct.unpack_from('B', data, 0x16c)[0]

    # Name
    start = 0x16e
    end = start + (name_len * 2)
    self.name = data[start:end].decode('utf-16')
    self.phone = self.__decode_phone(data)

  @staticmethod
  def __decode_digit(value):
    if value >= 0 and value <= 9:
      return str(value)
    if value == 10:
      return '*'
    if value == 15:
      return ''
    if value == 11:
      return '#'  # Just a guess
    raise ValueError('Unknown digit value {}'.format(value))

  def __decode_phone(self, data):
    phone_len, extra = struct.unpack_from('bb', data, 0x12a)
    phone = ''
    if extra & 0x10:
      phone += '+'
    for byte in data[0x12c:0x12c+phone_len]:
      phone += self.__decode_digit(byte & 0x0f)
      phone += self.__decode_digit(byte >> 4)
    return phone

  def vcard(self):
    return 'BEGIN:VCARD\nVERSION:3.0\nN:{name}\n' \
         'FN:{name}\nTEL;type=HOME:{phone}\n' \
         'END:VCARD\n'.format(name=self.name, phone=self.phone)

  def __str__(self):
    return '<Entry name={} phone={}>'.format(self.name, self.phone)


class IbFileData(object):
  def __init__(self):
    self.file = None
    self.header = None
    self.hdr_num_entries = None
    self.entry_heading = None
    self.offsets = None
    self.rel_offsets = None
    self.unique_rel_offsets = None
    self.entry_size = None
    self.analysis_str = None

ib_files = [] # will be populated with IbFileData objects


class hexdump:
  # https://gist.github.com/NeatMonster/c06c61ba4114a2b31418a364341c26c0
  def __init__(self, buf, off=0):
    self.buf = buf
    self.off = off
  def __iter__(self):
    last_bs, last_line = None, None
    for i in range(0, len(self.buf), 16):
      bs = bytearray(self.buf[i : i + 16])
      line = "{:08x}  {:23}  {:23}  |{:16}|".format(
        self.off + i,
        " ".join(("{:02x}".format(x) for x in bs[:8])),
        " ".join(("{:02x}".format(x) for x in bs[8:])),
        "".join((chr(x) if 32 <= x < 127 else "." for x in bs)),
      )
      if bs == last_bs:
        line = "*"
      if bs != last_bs or line != last_line:
        yield line
      last_bs, last_line = bs, line
    yield "{:08x}".format(self.off + len(self.buf))
  def __str__(self):
    return "\n".join(self)
  def __repr__(self):
    return "\n".join(self)


def dump_header(infile):
  infile.seek(0)
  header = infile.read(0x244) # 0x244 = 580 bytes header; .read changes file cursor position
  header_str = hexdump(header)
  print(header_str)
  next_four = infile.read(4)
  next_four_hex_bstr = binascii.hexlify(next_four, ' ')
  next_four_hex_str = next_four_hex_bstr.decode('utf-8') # same as 'ascii' here
  print("nextfour: {}".format(next_four_hex_str))

def analyze_file(infile):
  infile.seek(0)
  header = infile.read(0x244) # 0x244 = 580 bytes header; .read changes file cursor position
  next_four = infile.read(4)
  entry_heading = next_four[:2]
  eh_len = len(entry_heading)
  # two bytes at offset 0x30 (in header) should give number of entries as uint16_t LE
  hdr_num_entries = struct.unpack_from("<H", header, 0x30)[0]
  # read entire file in RAM, then search for entry headings, record relative offsets
  offsets = []
  offset = 0
  infile.seek(offset)
  file_bstr = infile.read()
  searching = True
  while searching:
    offset = file_bstr.find(entry_heading, offset)
    if offset < 0:
      searching = False
    else:
      offsets.append(offset)
      offset += eh_len
  #print(offsets)
  rel_offsets = tuple((x - y) for (x, y) in zip(offsets[1:], offsets[:-1]))
  #unique_rel_offsets = list(dict.fromkeys(rel_offsets)) # without counts
  unique_rel_offsets = dict(Counter(rel_offsets).items())
  # get key (rel offset size in bytes) where value (number of occurences) is max as assumed entry size
  entry_size = max(unique_rel_offsets, key=unique_rel_offsets.get)
  analysis_str = []
  analysis_str.append( "Number of entries (from offset 0x30 in header): {}".format(hdr_num_entries) )
  uniq_reloffs_strl = ["at relative offset {}: {} times".format(offs, cnt) for offs, cnt in unique_rel_offsets.items()]
  uniq_reloffs_str = "; ".join(uniq_reloffs_strl)
  eh_report = "Assumed entry heading (hex) {:02X} {:02X} occurs: {}".format(
    entry_heading[0], entry_heading[1], uniq_reloffs_str
  )
  analysis_str.append( eh_report )
  analysis_str.append( "Chosen assumed entry size is: {0:} (0x{0:04X})".format(entry_size) )
  #
  ibfile_data = IbFileData()
  ibfile_data.file = infile
  ibfile_data.header = header
  ibfile_data.hdr_num_entries = hdr_num_entries
  ibfile_data.entry_heading = entry_heading
  ibfile_data.offsets = offsets
  ibfile_data.rel_offsets = rel_offsets
  ibfile_data.unique_rel_offsets = unique_rel_offsets
  ibfile_data.entry_size = entry_size
  ibfile_data.analysis_str = analysis_str
  ib_files.append(ibfile_data)


def process(infile, outfile):
  header = infile.read(0x244) # 0x244 = 580 bytes header; .read changes file cursor position
  entries = 0
  while True:
    data_hdr = infile.read(2)
    if not data_hdr:
      break
    hdr = struct.unpack('BB', data_hdr)
    data_len = (
      (hdr[0] >> 4) * 100 + (hdr[0] & 0x0f) * 10 +
      (hdr[1] >> 4))
    data = data_hdr + infile.read(data_len - 2)
    entry = Entry(data)
    outfile.write(entry.vcard())
    entries += 1
  print('Exported {} entries.'.format(entries))



def main():
  parser = argparse.ArgumentParser(
    description='Nokia 3310 phonebook.ib exporter. If no --outfile is specified, loop through the input files and print path and file size (can also use --hexdump and --print-analysis in this case).')
  parser.add_argument('infiles', type=argparse.FileType('rb'),
            help='Phonebook ,ib files to read', nargs='+')
  parser.add_argument('-o', '--outfile', type=argparse.FileType('w', encoding='utf8'),
            help='VCF File to write')
  parser.add_argument('-x', '--hexdump', action='store_true',
            help='print hexdump of the header to stdout')
  parser.add_argument('-a', '--print-analysis', action='store_true',
            help='print analysis results to stdout')
  args = parser.parse_args()
  # perform analysis regardless
  for infile in args.infiles:
    analyze_file(infile)

  if not(args.outfile):
    for ib_file in ib_files:
      infile = ib_file.file
      print(os.path.abspath(infile.name))
      file_size = os.fstat(infile.fileno()).st_size
      print("  File size: {0} (0x{0:06X})".format(file_size))
      if args.hexdump:
        dump_header(infile)
      if args.print_analysis:
        print("\n".join(ib_file.analysis_str))
      print()
    if args.print_analysis:
      # print a comparison between number of entries from header vs counted number of entries
      # seemingly, if there are no differing rel_offsets, then header == counted+1
      # (unless header == counted == 1); else header == sum(counted)
      print("Number of entries comparison:")
      for ib_file in ib_files:
        counts_list = tuple(ib_file.unique_rel_offsets.values())
        counts_list_str = "+".join(map(str, counts_list))
        if len(counts_list)>1:
          counts_list_sum = sum(counts_list)
          counts_list_str += " ( = {})".format(counts_list_sum)
        print("  Header: {} <-> counted: {}".format(
          ib_file.hdr_num_entries, counts_list_str
        ))
  #process(args.infile, args.outfile)

if __name__ == '__main__':
  main()
