#!/usr/bin/env python3
# Modified to support Nokia TA-1279 (entry signature 0x38 0x02)

import sys, os
import argparse
from argparse import RawDescriptionHelpFormatter
import struct
import binascii
from collections import Counter
from collections import OrderedDict
import json

HELP_TEXT = """Nokia phonebook.ib exporter with TA-1279 support.

Supports: Nokia 3310 3G, Nokia 220 4G, Nokia TA-1279, and similar models.
"""

class Entry(object):
  def __init__(self, data):
    self.hdr = struct.unpack_from('BB', data, 0x0)
    
    # Default offsets (Nokia 3310 3G - 0x98/0x94, 0x03)
    self.name_len_offset = 0x16c
    self.name_start = 0x16e
    self.phone_len_offset = 0x12a
    self.phone_start = 0x12c
    self.extra1_len_offset = 0x1c0
    self.extra1_start = 0x1c2
    
    # Nokia 220 4G (0xBC, 0x00)
    if self.hdr == (0xBC, 0x00):
      self.name_len_offset = 0x4a
      self.name_start = 0x4c
      self.phone_len_offset = 0x1d
      self.phone_start = 0x1f
      self.extra1_len_offset = 0x8a
      self.extra1_start = 0x8c
    
    # Nokia TA-1279 (0x38, 0x02)
    elif self.hdr == (0x38, 0x02):
      self.name_len_offset = 0x60
      self.name_start = 0x62
      self.phone_len_offset = 0x1e
      self.phone_start = 0x20
      self.extra1_len_offset = 0xb8
      self.extra1_start = 0xba - 4  # Adjust by 4 bytes based on observed truncation

    # Read name length - for TA-1279 main name uses uint16
    name_len = struct.unpack_from('<H', data, self.name_len_offset)[0]
    
    # For extra1, read as single byte
    extra1_len = struct.unpack_from('B', data, self.extra1_len_offset)[0]

    # Name
    start = self.name_start
    end = start + (name_len * 2)
    try:
      self.name = data[start:end].decode('utf-16-le', errors='ignore').rstrip('\x00')
    except:
      self.name = ""
    
    self.phone = self.__decode_phone(data)
    
    extra1_start = self.extra1_start  
    extra1_end = extra1_start + (extra1_len * 2)
    try:
      self.extra1 = data[extra1_start:extra1_end].decode('utf-16-le', errors='ignore').rstrip('\x00')
    except:
      self.extra1 = ""

  @staticmethod
  def __decode_digit(value):
    if value >= 0 and value <= 9:
      return str(value)
    if value == 10:
      return '*'
    if value == 15:
      return ''
    if value == 11:
      return '#'
    raise ValueError('Unknown digit value {}'.format(value))

  def __decode_phone(self, data):
    phone_len, extra = struct.unpack_from('bb', data, self.phone_len_offset)
    phone_start = self.phone_start
    phone = ''
    if extra & 0x10:
      phone += '+'
    for byte in data[phone_start:phone_start+phone_len]:
      phone += self.__decode_digit(byte & 0x0f)
      phone += self.__decode_digit(byte >> 4)
    return phone

  def vcard(self):
    return 'BEGIN:VCARD\r\nVERSION:2.1\r\n' \
         'N;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:;{name};;;\r\n' \
         'FN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:{name}\r\n' \
         'TEL;HOME:{phone}\r\n' \
         'END:VCARD\r\n'.format(name=self.name, phone=self.phone)

  def __str__(self):
    return '<Entry name={} phone={}>'.format(self.name, self.phone)


class IbFileData(object):
  def __init__(self):
    self.file = None
    self.file_size = None
    self.header = None
    self.contents = None
    self.hdr_num_entries = None
    self.entry_heading = None
    self.offsets = None
    self.rel_offsets = None
    self.unique_rel_offsets = None
    self.entry_size = None
    self.analysis_str = None
    self.b_entries = None
    self.entries = None
    self.entries_parse_log = None

ib_files = []

from json import JSONEncoder
def _default(self, obj):
  return getattr(obj.__class__, "to_json", _default.default)(obj)
_default.default = JSONEncoder().default
JSONEncoder.default = _default

class OrderedClassMembers(type):
  @classmethod
  def __prepare__(self, name, bases):
    return OrderedDict()
  def __new__(self, name, bases, classdict):
    classdict['__ordered__'] = [key for key in classdict.keys()
      if key not in ('__module__', '__qualname__')]
    return type.__new__(self, name, bases, classdict)

class OrderedObjectDict(metaclass=OrderedClassMembers):
  def __setattr__(self, name, value):
    self.__dict__[name] = value
  def __getattr__(self, name):
    return self.__dict__[name]
  def __getitem__(self, name):
    return self.__dict__[name]
  def __setitem__(self, name, value):
    self.__dict__[name] = value
  def keys(self):
    return self.__dict__.keys()
  def to_json(self):
    return self.__dict__

class IPBEntry(OrderedObjectDict):
  def __init__(self, name=None, phone=None, eref=None):
    self.name = ""
    if name is not None:
      self.name = name
    self.phone = ""
    if phone is not None:
      self.phone = phone
    self.eref = None
    if eref is not None:
      self.eref = eref
    self.iduplicates = 0

  def has_same_content(self, in_ipb_entry):
    if ( (self.name == in_ipb_entry.name) and (self.phone == in_ipb_entry.phone) ):
      return True
    else:
      return False

  def __str__(self):
    return "<IPBEntry name='{}' phone='{}' iduplicates={}>".format(self.name, self.phone, self.iduplicates)

  def __repr__(self):
    return "<IPBEntry name='{}' phone='{}' iduplicates={}>".format(self.name, self.phone, self.iduplicates)

  def to_json(self):
    clean_dict = OrderedDict( tuple((key, value) for key, value in self.__dict__.items() if key not in ("eref",)) )
    return clean_dict

  def vcard(self):
    return 'BEGIN:VCARD\r\nVERSION:2.1\r\n' \
         'N;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:;{name};;;\r\n' \
         'FN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:{name}\r\n' \
         'TEL;HOME:{phone}\r\n' \
         'END:VCARD\r\n'.format(name=self.name, phone=self.phone)

merged_ipb_entries = []


class hexdump:
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
  header = infile.read(0x244)
  header_str = hexdump(header)
  print(header_str)
  next_four = infile.read(4)
  next_four_hex_bstr = binascii.hexlify(next_four, ' ')
  next_four_hex_str = next_four_hex_bstr.decode('utf-8')
  print("nextfour: {}".format(next_four_hex_str))

def analyze_file(infile):
  file_size = os.fstat(infile.fileno()).st_size
  infile.seek(0)
  header = infile.read(0x244)
  next_four = infile.read(4)
  entry_heading = next_four[:2]
  eh_len = len(entry_heading)
  hdr_num_entries = struct.unpack_from("<H", header, 0x30)[0]
  b_entries = []
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
  last_offset_idx = len(offsets)-1
  for ioff, offset in enumerate(offsets):
    if ioff == last_offset_idx:
      break
    next_offset = offsets[ioff+1]
    this_entry_slice = file_bstr[offset:next_offset]
    b_entries.append(this_entry_slice)
  last_offset = offsets[last_offset_idx]
  last_bytes_delta = file_size - last_offset
  if last_bytes_delta > 1:
    b_entries.append(file_bstr[last_offset:file_size-1])
  rel_offsets = tuple((x - y) for (x, y) in zip(offsets[1:], offsets[:-1]))
  unique_rel_offsets = dict(Counter(rel_offsets).items())
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
  analysis_str.append( "Last offset is {:7d} for file size {:7d}".format(last_offset, file_size) )
  ibfile_data = IbFileData()
  ibfile_data.file = infile
  ibfile_data.file_size = file_size
  ibfile_data.header = header
  ibfile_data.contents = file_bstr
  ibfile_data.hdr_num_entries = hdr_num_entries
  ibfile_data.entry_heading = entry_heading
  ibfile_data.offsets = offsets
  ibfile_data.rel_offsets = rel_offsets
  ibfile_data.unique_rel_offsets = unique_rel_offsets
  ibfile_data.entry_size = entry_size
  ibfile_data.analysis_str = analysis_str
  ibfile_data.b_entries = b_entries
  ibfile_data.entries = []
  ibfile_data.entries_parse_log = []
  ib_files.append(ibfile_data)
  parse_file_entries(ibfile_data)

def parse_file_entries(ib_file):
  ibf = ib_file
  ibf.entries = []
  eplog = ibf.entries_parse_log = []
  for ibe, b_entry_data in enumerate(ibf.b_entries):
    n_ibe = ibe + 1
    try:
      entry = Entry(b_entry_data)
    except Exception as e:
      hexstr = ""
      eplog.append("-- cannot parse entry {} with {} bytes; ignoring ({}){}".format(n_ibe, len(b_entry_data), e, hexstr))
      continue
    
    # Combine name and extra1 - if main name is empty, use extra1 as the primary name
    fullname = entry.name.strip()
    extra_name = entry.extra1.strip()
    
    if not fullname and extra_name:
      # Main name empty, use extra as primary
      fullname = extra_name
    elif fullname and extra_name and fullname != extra_name:
      # Both exist and different, combine them
      fullname = fullname + " " + extra_name
    
    eplog.append("-- entry {}, {} bytes: name: '{}' phone: '{}'".format(n_ibe, len(b_entry_data), fullname, entry.phone))
    ibf.entries.append(entry)
    
    ipb_entry = IPBEntry(fullname, entry.phone, entry)
    identical_ipb_entry_found = False
    for tpb_entry in merged_ipb_entries:
      if tpb_entry.has_same_content(ipb_entry):
        identical_ipb_entry_found = True
        tpb_entry.iduplicates += 1
        break
    if not(identical_ipb_entry_found):
      merged_ipb_entries.append(ipb_entry)


def main():
  global merged_ipb_entries
  parser = argparse.ArgumentParser( formatter_class=RawDescriptionHelpFormatter,
    description=HELP_TEXT)
  parser.add_argument('infiles', type=argparse.FileType('rb'),
            help='Phonebook .ib files to read', nargs='*')
  parser.add_argument('-o', '--outfile', type=argparse.FileType('w', encoding='utf8'),
            help='VCF File to write')
  parser.add_argument('-x', '--hexdump', action='store_true',
            help='print hexdump of an .ib file header to stdout')
  parser.add_argument('-a', '--print-analysis', action='store_true',
            help='print analysis results to stdout')
  parser.add_argument('-e', '--print-log-entries', action='store_true',
            help='print log entries parsing results to stdout')
  parser.add_argument('-j', '--outjson', type=argparse.FileType('w', encoding='utf8'),
            help='Output intermediate contacts collection to .json file')
  parser.add_argument('-i', '--injson', type=argparse.FileType('r', encoding='utf8'),
            help='Read injson file to reconstruct contacts')
  args = parser.parse_args()

  if (args.injson):
    print("")
    print("Received --injson: skipping parse of .ib infiles, reconstructing from:")
    print("  {}".format( os.path.abspath(args.injson.name) ))
    merged_ipb_entries_load = json.load(args.injson)
    merged_ipb_entries = []
    for tmipbe in merged_ipb_entries_load:
      tipbe = IPBEntry(tmipbe["name"], tmipbe["phone"])
      merged_ipb_entries.append(tipbe)
  else:
    for infile in args.infiles:
      analyze_file(infile)

    len_ib_files = len(ib_files)
    for ibf, ib_file in enumerate(ib_files):
      n_ibf = ibf + 1
      infile = ib_file.file
      print(os.path.abspath(infile.name))
      eh = ib_file.entry_heading
      print("  File {0:3d}/{1:3d} filesize: {2:7d} (0x{2:06X}) ; entry sig {3:02X} {4:02X}".format(n_ibf, len_ib_files, ib_file.file_size, eh[0], eh[1]))
      err_lines = [line for line in ib_file.entries_parse_log if line.startswith("-- cannot")]
      len_err_lines = len(err_lines)
      print("  Parsed entries: {:4d} (out of {:4d} header expected); parse errors {}".format(len(ib_file.entries), ib_file.hdr_num_entries, len_err_lines))
      if args.hexdump:
        dump_header(infile)
      if args.print_analysis:
        print("\n".join(ib_file.analysis_str))
      if args.print_log_entries:
        print("\n".join(ib_file.entries_parse_log))
      else:
        if len_err_lines>0:
          print("\n".join(err_lines))
      if (n_ibf != len_ib_files):
        print("")
    if args.print_analysis:
      print("")
      print("Number of entries comparison:")
      all_entry_sizes = []
      all_entry_headings = []
      for ib_file in ib_files:
        counts_list = tuple(ib_file.unique_rel_offsets.values())
        counts_list_str = "+".join(map(str, counts_list))
        if len(counts_list)>1:
          counts_list_sum = sum(counts_list)
          counts_list_str += " ( = {})".format(counts_list_sum)
        print("  Header: {:4d} <-> split: {:4d} counted: {}".format(
          ib_file.hdr_num_entries, len(ib_file.b_entries), counts_list_str
        ))
        all_entry_sizes.append(ib_file.entry_size)
        all_entry_headings.append(ib_file.entry_heading)
      uniq_entry_sizes = list(set(all_entry_sizes))
      uniq_entry_headings = list(set(all_entry_headings))
      uniq_entry_headings_str = ["0x{:02X} 0x{:02X}".format(eh[0], eh[1]) for eh in uniq_entry_headings]
      print("Unique entry sizes ({}): {}".format(
        len(uniq_entry_sizes), ", ".join(map(str, uniq_entry_sizes))
      ))
      print("Unique entry headings ({}): {}".format(
        len(uniq_entry_headings), " ; ".join(uniq_entry_headings_str)
      ))
    print("")
    print("Files processed: {:3d}".format(len_ib_files))

  ipbentries_with_empties = []
  for ipbe in merged_ipb_entries:
    # Only remove if BOTH name AND phone are empty
    if not(ipbe.name) and not(ipbe.phone):
      ipbentries_with_empties.append(ipbe)
    # If name is empty but phone exists, use phone as name
    elif not(ipbe.name) and ipbe.phone:
      ipbe.name = ipbe.phone
  if len(ipbentries_with_empties):
    print("")
    for ipbee in ipbentries_with_empties:
      print("Removing entry with empty fields: {}".format(ipbee))
      merged_ipb_entries.remove(ipbee)

  uniq_names = {}
  num_duplicate_names = 0
  for ipbe in merged_ipb_entries:
    if ipbe.name not in uniq_names.keys():
      uniq_names[ipbe.name] = [ipbe]
    else:
      uniq_names[ipbe.name] += [ipbe]
  if len(uniq_names.keys()):
    print("")
    for tuname in uniq_names.keys():
      if len(uniq_names[tuname]) > 1:
        print("WARNING: Duplicate name '{}': {}".format(tuname, uniq_names[tuname]))
        num_duplicate_names += 1

  uniq_phones = {}
  num_duplicate_phones = 0
  for ipbe in merged_ipb_entries:
    phone_found = ""
    for tupkey in uniq_phones.keys():
      if len(ipbe.phone)>6 and ipbe.phone in tupkey:
        phone_found = tupkey
        break
    if not(phone_found):
      uniq_phones[ipbe.phone] = [ipbe]
    else:
      uniq_phones[phone_found] += [ipbe]
  if len(uniq_phones.keys()):
    print("")
    for tuphone in uniq_phones.keys():
      if len(uniq_phones[tuphone]) > 1:
        print("WARNING: Duplicate phone '{}': {}".format(tuphone, uniq_phones[tuphone]))
        num_duplicate_phones += 1

  all_duplicate_counts = [ipbe.iduplicates for ipbe in merged_ipb_entries]
  unique_duplicate_counts = dict(Counter(all_duplicate_counts).items())
  print("")
  print("Extracted entries: {:5d} (removed empty field entries: {}; found duplicate counts: {})".format(
    len(merged_ipb_entries), len(ipbentries_with_empties), unique_duplicate_counts
  ))
  print("                   Found total duplicate name entries: {}; duplicate phone entries: {}".format(
    num_duplicate_names, num_duplicate_phones
  ))

  if args.outjson or args.outfile:
    merged_ipb_entries.sort(key=lambda x: x.name.lower(), reverse=False)

  if args.outjson:
    json.dump(merged_ipb_entries, args.outjson, ensure_ascii=False, indent=2)
    print("")
    print("Wrote {} JSON entries to {}".format(len(merged_ipb_entries), os.path.abspath(args.outjson.name)))

  if args.outfile:
    for ipbe in merged_ipb_entries:
      args.outfile.write( ipbe.vcard() )
    print("")
    print("Wrote {} VCF entries to {}".format(len(merged_ipb_entries), os.path.abspath(args.outfile.name)))


if __name__ == '__main__':
  main()
