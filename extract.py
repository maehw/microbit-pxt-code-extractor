from argparse import ArgumentParser
from io import StringIO
from re import sub
from intelhex import IntelHex
from json import loads, dumps
import lzma

if __name__ == '__main__':
    parser = ArgumentParser(description='%(prog)s')

    parser.add_argument('-f',
                        action="store",
                        required=True,
                        dest='file',
                        help='path to bbc micro:bit HEX file')

    args = parser.parse_args()

    # open the HEX file and read all lines from it
    fhandle = open(args.file, 'r')
    lines = fhandle.readlines()

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
    print(f"{'-'*73}")
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

    print("JSON header:")
    header_offset = 16
    json_header = ih.tobinstr(start=header_offset, size=header_len)
    json_header = loads( json_header.decode('utf-8') )
    print( dumps(json_header, indent=4) )

    print(f"{'-'*73}")
    print("Text:")

    code_text = ih.tobinstr(start=header_offset+header_len)
    #print(code_text)

    if "LZMA" == json_header['compression']:
        print("  Text is LZMA-compressed")

        # Lempel–Ziv–Markov chain algorithm (LZMA) has a 13 byte header
        # - Properties (single byte)
        # - Dictionary size (32 bit, i.e. 4 bytes)
        # - Uncompressed size (64 bit, i.e. 8 bytes)

        # 'The value of the lclppb byte is lc + lp * 9 + pb * 9 * 5'
        print( f"         Properties: {code_text[0]:02X}" )

        dict_size = int(f"{code_text[3]:02X}{code_text[2]:02X}{code_text[1]:02X}{code_text[0]:02X}", 16)
        print( f"    Dictionary size: 0x{code_text[1]:02X}{code_text[2]:02X}{code_text[3]:02X}{code_text[4]:02X} ({dict_size})" )

        uncompr_size = int(f"{code_text[12]:02X}{code_text[11]:02X}{code_text[10]:02X}{code_text[9]:02X}{code_text[8]:02X}{code_text[7]:02X}{code_text[6]:02X}{code_text[5]:02X}", 16)
        print( f"  Uncompressed size: 0x{code_text[5]:02X}{code_text[6]:02X}{code_text[7]:02X}{code_text[8]:02X}{code_text[9]:02X}{code_text[10]:02X}{code_text[11]:02X}{code_text[12]:02X} ({uncompr_size})" )

        #lzma.decompress(code_text) #, format=lzma.FORMAT_RAW, filters=[{'id': lzma.FILTER_LZMA2}])

        with open("binary.lzma", "wb") as binary_file:
            binary_file.write(code_text)

        # print(code_text)
