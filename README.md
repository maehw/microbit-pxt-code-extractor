# bbc micro:bit PXT code extractor

This project attempts to extract the code from so called [Universal Hex files](https://tech.microbit.org/software/spec-universal-hex/) generated by the [PXT-based](https://github.com/microsoft/pxt) Microsoft MakeCode IDE for micro:bit ([web IDE](https://makecode.microbit.org/)). PXT uses a technique called [source embedding](https://github.com/Microsoft/pxt/blob/437f53ca6311335c7f3f75a062ec1079b4e7806a/docs/source-embedding.md) in order to add the code as (possibly compressed) text into the `0x0D`("Custom Data") records of an Intel HEX file.

The code extractor itself is realized as Python 3 script.

This project is not supporting the extraction of Python code from the BBC micro:bit. To do so, the [uBitTool](https://github.com/carlosperate/ubittool). As soon as the PXT code extractor is working, it may be added to the uBitTool - feel free to create a pull request.


## Usage

* Clone this git repository
* Make sure the Python module dependencies are met: `pip3 install intelhex argparse lzma`
* Run the script from a Python 3 environment (should be runnable under Windows, Linux and MacOS):

```
  usage: extract.py [-h] -f FILE
```

  Example:

```
  python extract.py -f /Users/maehw/sound-device.hex
  Embedded source dump:
  -------------------------------------------------------------------------
  0000  41 14 0E 2F B8 2F A2 BB 9D 00 71 09 00 00 00 00  |A.././....q.....|
  0010  7B 22 63 6F 6D 70 72 65 73 73 69 6F 6E 22 3A 22  |{"compression":"|
  0020  4C 5A 4D 41 22 2C 22 68 65 61 64 65 72 53 69 7A  |LZMA","headerSiz|
  0030  65 22 3A 31 35 36 2C 22 74 65 78 74 53 69 7A 65  |e":156,"textSize|
  0040  22 3A 31 35 31 30 32 2C 22 6E 61 6D 65 22 3A 22  |":15102,"name":"|
  0050  73 6F 75 6E 64 2D 64 65 76 69 63 65 22 2C 22 65  |sound-device","e|
  0060  55 52 4C 22 3A 22 68 74 74 70 73 3A 2F 2F 6D 61  |URL":"https://ma|
  0070  6B 65 63 6F 64 65 2E 6D 69 63 72 6F 62 69 74 2E  |kecode.microbit.|
  0080  6F 72 67 2F 22 2C 22 65 56 45 52 22 3A 22 35 2E  |org/","eVER":"5.|
  0090  30 2E 31 32 22 2C 22 70 78 74 54 61 72 67 65 74  |0.12","pxtTarget|
  00A0  22 3A 22 6D 69 63 72 6F 62 69 74 22 7D 5D 00 00  |":"microbit"}]..|
  00B0  80 00 A3 3B 00 00 00 00 00 00 00 3D 88 89 C6 54  |...;.......=...T|
  00C0  36 C3 17 4F E4 F9 EC 0D 07 A9 22 3E D4 1C 7C B5  |6..O......">..|.|
  00D0  AF A5 88 58 62 DF 18 4A B0 53 1D A2 B3 BA 13 --  |...Xb..J.S..... |
  ...
  -------------------------------------------------------------------------
  JSON header length: 0x9D00 (157)
         Text length: 0x71090000 (2417)
            Reserved: 0x0000
  -------------------------------------------------------------------------
  JSON header:
  {
      "compression": "LZMA",
      "headerSize": 156,
      "textSize": 15102,
      "name": "sound-device",
      "eURL": "https://makecode.microbit.org/",
      "eVER": "5.0.12",
      "pxtTarget": "microbit"
  }
  -------------------------------------------------------------------------
  Text:
    Text is LZMA-compressed
           Properties: 5D
      Dictionary size: 0x00008000 (2147483741)
    Uncompressed size: 0xA33B000000000000 (15267)
```

## Known issues

The LZMA decompression does not work yet.
As stated in the "Source Embedding" document, PXT always LZMA-compresses the text.
So up until now this is the dead end.

## Contribution

Feel free to make any changes and support this project. ;)