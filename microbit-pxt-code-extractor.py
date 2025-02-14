#!/usr/bin/env python3

from argparse import ArgumentParser
from io import StringIO
from re import sub
from intelhex import IntelHex
from json import loads, dumps
from pathlib import Path
import lzma
import os

if __name__ == '__main__':
    parser = ArgumentParser(description='%(prog)s')

    parser.add_argument(nargs='?',
                        dest='file',
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
    print(f"           Output folder: {out_folder}")
    print(f"{'-'*73}")

    Path(out_folder).mkdir(parents=True, exist_ok=True)

    # add extracted lines to a large string
    extracted_lines = ""
    for line in lines:
        # - convert record type 0x0E (Universal Hex Format Specification, "Other Data")
        #        to record type 0x00 (default Intel HEX "Data")
        # - and only keep those lines
        # - re-calculate checksum for those lines
        #   (discard the last two HEX digits from group '\g<3>',
        #    re-calculate checksum and add the new HEX digits and a newline character)
        line_modified = sub('^(:[0-9a-fA-F]{6})0[eE]([0-9a-fA-F]*)([0-9a-fA-F]{2})', r"\g<1>00\g<2>", line)
        if line != line_modified:
            # print(f"Original line:     {line}")
            # print(f"    Modified line: {line_modified}")

            # do not count newline characters and not the colon (':') at the start of line
            # TODO/FIXME: make this code more efficient
            checksum = 0
            line_modified = line_modified.strip()
            num_chars = len(line_modified)-1
            assert(num_chars % 2 == 0)
            for k in range(0, int(num_chars/2)):
                checksum += int(f"{line_modified[2*k + 1]}{line_modified[2*k + 2]}", 16)
            checksum = checksum % 256 # checksum is only 8 bits
            checksum = ~checksum + 1  # calculate two's complement
            checksum = f"{(checksum & ((1 << 8)-1)):02X}" # format as 2 digit HEX number
            # print(f"    Checksum: {checksum}")

            line_modified = f"{line_modified}{checksum}\n"
            # print(f"    Modified line: {line_modified}")
            extracted_lines += line_modified

    # create a virtual file from the large string for further access by intelhex module
    virtual_hex_file = StringIO(extracted_lines)

    ih = IntelHex(virtual_hex_file)

    print("Embedded source dump:")
    #ih.dump() # dump the whole file
    ih[0:0xDF].dump() # only show some lines
    print("...")

    file_hexstr = f"{ih[0]:02X}{ih[1]:02X}{ih[2]:02X}{ih[3]:02X}{ih[4]:02X}{ih[5]:02X}{ih[6]:02X}{ih[7]:02X}"
    assert("41140E2FB82FA2BB" == file_hexstr)

    print(f"{'-'*73}")

    header_len = int(f"{ih[ 9]:02X}{ih[ 8]:02X}", 16)
    print(f"JSON header length: 0x{ih[ 8]:02X}{ih[ 9]:02X} ({header_len})")
    text_len = int(f"{ih[13]:02X}{ih[12]:02X}{ih[11]:02X}{ih[10]:02X}", 16)
    print(f"       Text length: 0x{ih[10]:02X}{ih[11]:02X}{ih[12]:02X}{ih[13]:02X} ({text_len})")
    print(f"          Reserved: 0x{ih[14]:02X}{ih[15]:02X}")

    assert("0000" == f"{ih[14]:02X}{ih[15]:02X}")

    print(f"{'-'*73}")

    print("Embedded JSON header (pretty-printed):")
    header_offset = 16
    json_header = ih.tobinstr(start=header_offset, size=header_len)
    json_header = loads( json_header.decode('utf-8') )
    print( dumps(json_header, indent=json_indent) )
    header_size = 0
    if json_header['headerSize']:
        header_size = int(json_header['headerSize'])
        print(f"Header size: {header_size}")
    text_size = 0
    if json_header['textSize']:
        text_size = int(json_header['textSize'])
        print(f"Text size: {text_size}")

    print(f"{'-'*73}")
    print("Text meta data:")

    code_text = ih.tobinstr(start=header_offset+header_len)
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

    print(f"{'-'*73}")
    print("Code header dump (pretty-printed)")
    code_header = loads(code_text[:header_size])
    print( dumps(code_header, indent=json_indent) )

    with open(out_folder.joinpath("_code_header.json"), "w") as code_header_file:
        print(f"Writing code header JSON file...")
        code_header_file.write( dumps(code_header) )

    print(f"{'-'*73}")
    print("Code payload analysis (pretty-printed)")
    code_payload = code_text[header_size:]
    print(f"  Length: {len(code_payload)}")
    code_payload_json = loads(code_payload)
    output_files = list(code_payload_json.keys())
    print(f"   Files: {output_files}")
    for output_file in output_files:
        with open(out_folder.joinpath(output_file), "w") as current_file:
            print(f"Writing file '{output_file}'...")
            current_file.write( dumps(code_payload_json.get(output_file)) )
