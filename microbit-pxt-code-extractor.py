#!/usr/bin/env python3

from argparse import ArgumentParser
from io import StringIO
from re import sub
from intelhex import IntelHex
from json import loads, dumps
from pathlib import Path
import lzma
import os


def sep():
    print(f"{'-' * 73}")


if __name__ == '__main__':
    parser = ArgumentParser(description='%(prog)s')

    parser.add_argument('file',
                        action='store',
                        help='path to bbc micro:bit HEX input file')

    args = parser.parse_args()
    json_indent = 4

    # open the HEX file and read all lines from it
    fhandle = open(args.file, 'r')
    lines = fhandle.readlines()

    # create output directory
    filename = Path(args.file)
    out_folder = filename.parents[0].joinpath(filename.stem)
    out_folder = Path(os.getcwd()).joinpath(filename.stem)
    print(f"Input file w/o extension: {filename.stem}")

    file_stats = os.stat(args.file)
    print(f'  HEX file size in bytes: {file_stats.st_size}')

    print(f"     HEX file line count: {len(lines)}")

    print(f"           Output folder: {out_folder}")
    sep()

    Path(out_folder).mkdir(parents=True, exist_ok=True)

    # add extracted lines to a large string making up the contents of a new "virtual HEX file"
    extracted_lines = ""
    for line in lines:
        # - convert record type 0x0E (Universal Hex Format Specification, "Other Data")
        #        to record type 0x00 (default Intel HEX "Data")
        # - and only keep those lines
        # - re-calculate checksum for those lines
        #   (discard the old checksum, i.e. the last two HEX digits from group '\g<3>',
        #  - re-calculate checksum and add the new HEX digits and a newline character)
        #
        # details about Intel HEX and hence the following regex:
        # - every line starts with start code ':'
        # - followed by a 2 HEX digit byte count
        # - followed by a 4 HEX digit address
        # - followed by a 2 HEX digit type (the 0x0e/0x0E we're heading for)
        # - several pairs of HEX digits of the actual data
        # - ending with a 2 HEX digit checksum
        line_modified = sub('^(:[0-9a-fA-F]{6})0[eE]([0-9a-fA-F]*)([0-9a-fA-F]{2})', r"\g<1>00\g<2>", line)
        if line != line_modified:
            # the current line matched the regex and therefore contains relevant info, let's have a closer look
            #print(f"Original line:     {line}")
            #print(f"    Modified line: {line_modified}")

            # do not count newline characters and not the colon (':') at the start of line;
            # make sure HEX digits come in pairs so that no HEX digits remains and always two nibbles make up one byte
            line_modified = line_modified.strip()
            num_chars = len(line_modified) - 1
            assert (num_chars % 2 == 0)

            # TODO/FIXME: make the checksum re-calculation more efficient
            checksum = 0
            for k in range(0, int(num_chars / 2)):
                checksum += int(f"{line_modified[2 * k + 1]}{line_modified[2 * k + 2]}", 16)
            checksum = checksum % 256  # checksum is only 8 bits
            checksum = ~checksum + 1  # calculate two's complement
            checksum = f"{(checksum & ((1 << 8) - 1)):02X}"  # format as 2 digit HEX number
            # print(f"    Checksum: {checksum}")

            line_modified = f"{line_modified}{checksum}\n"
            # print(f"    Modified line: {line_modified}")
            extracted_lines += line_modified

    print(f"New virtual HEX file size in bytes: {len(extracted_lines)}")
    sep()

    # create a virtual file from the large string for further access by intelhex module
    virtual_hex_file = StringIO(extracted_lines)

    ih = IntelHex(virtual_hex_file)

    print("Embedded source dump:")
    # ih.dump() # dump the whole file
    ih[0:0xDF].dump()  # only show some lines
    print("...")

    # first 8 bytes (16 HEX digits in the HEX file) seem to make up a constant magic
    file_hexstr = f"{ih[0]:02X}{ih[1]:02X}{ih[2]:02X}{ih[3]:02X}{ih[4]:02X}{ih[5]:02X}{ih[6]:02X}{ih[7]:02X}"
    assert "41140E2FB82FA2BB" == file_hexstr, "Magic does not match"

    sep()

    header_len = int(f"{ih[9]:02X}{ih[8]:02X}", 16)
    print(f"JSON header length: 0x{ih[8]:02X}{ih[9]:02X} ({header_len})")
    text_len = int(f"{ih[13]:02X}{ih[12]:02X}{ih[11]:02X}{ih[10]:02X}", 16)
    print(f"       Text length: 0x{ih[10]:02X}{ih[11]:02X}{ih[12]:02X}{ih[13]:02X} ({text_len})")
    print(f"          Reserved: 0x{ih[14]:02X}{ih[15]:02X}")

    assert "0000" == f"{ih[14]:02X}{ih[15]:02X}", "Cannot handle reserved part"

    sep()

    print("Embedded JSON header (pretty-printed):")
    header_offset = 16
    json_header = ih.tobinstr(start=header_offset, size=header_len)
    json_header = loads(json_header.decode('utf-8'))
    print(dumps(json_header, indent=json_indent))
    header_size = 0
    if json_header['headerSize']:
        header_size = int(json_header['headerSize'])
        print(f"Header size: {header_size}")
    text_size = 0
    if json_header['textSize']:
        text_size = int(json_header['textSize'])
        print(f"Text size: {text_size}")

    sep()
    print("Text meta data:")

    code_text = ih.tobinstr(start=header_offset + header_len)
    print(f"  Length of text before truncation: {len(code_text)}")
    code_text = code_text[:text_len]
    print(f"   Length of text after truncation: {len(code_text)}")

    if "LZMA" == json_header['compression']:
        print("  Text is LZMA-compressed.")
        with open(out_folder.joinpath("_lzma_compressed_text.bin"), "wb") as text_file:
            print(f"  Writing LZMA compressed output text...")
            text_file.write(code_text)

        print("  Decompressing LZMA text...")
        code_text = lzma.decompress(code_text)

    with open(out_folder.joinpath("_packed_code.txt"), "wb") as text_file:
        print(f"Writing packed code...")
        text_file.write(code_text)

    sep()
    print("Code header dump (pretty-printed)")

    # find header end dynamically by looking for JSON pattern in string
    # warning: may not be safe for the future and need some adaption here!
    header_end_pos = code_text.find(b'}}')
    assert header_end_pos != -1, "Cannot find header end"
    header_end_pos += 2  # add two bytes because of the search pattern itself

    if header_size != header_end_pos:
        header_size = header_end_pos
        print(f"[WARNING] encoded header size is wrong, using {header_size} instead")

    code_header = loads(code_text[:header_size])
    print(dumps(code_header, indent=json_indent))

    with open(out_folder.joinpath("_code_header.json"), "w") as code_header_file:
        print(f"Writing code header JSON file...")
        code_header_file.write(dumps(code_header))

    sep()
    print("Code payload analysis (pretty-printed)")
    code_payload = code_text[header_size:]
    print(f"  Length: {len(code_payload)}")
    code_payload_json = loads(code_payload)
    output_files = list(code_payload_json.keys())
    print(f"   Files: {output_files}")
    for output_file in output_files:
        # replace characters that cause trouble
        replacement_character = "-"
        output_file = output_file.replace("~", replacement_character)
        output_file = output_file.replace("/", replacement_character)
        output_file = output_file.replace("\\", replacement_character)
        with open(out_folder.joinpath(output_file), "w") as current_file:
            print(f"Writing file '{output_file}'...")
            current_file.write(dumps(code_payload_json.get(output_file)))
