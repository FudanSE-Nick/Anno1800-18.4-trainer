#!/usr/bin/env python3
"""
a7s2xml - converts Anno 1800 save games (.a7s) to XML.

File layout (reverse engineered):

  .a7s file
   |- RDA "Resource File V2.2" container
   |   |- meta.a7s      (save name, version, timestamp)
   |   |- header.a7s    (save header / minimap etc.)
   |   |- gamesetup.a7s (game setup, players, difficulty settings)
   |   `- data.a7s      (the actual game state, ~45 MB)
   |
   |- every inner file: consecutive zlib streams + empty zlib stream + uint32 total size
   `- decompressed payload: Anno "FileDB" binary XML format

FileDB node layout (8 byte header, content padded to 8 bytes):
    uint32 size, uint16 id, uint16 reserved
      id == 0        -> closing tag
      id &  0x8000   -> leaf node, followed by `size` bytes of content
      otherwise      -> opening tag (size == 0)
The 20 byte trailer at the end of the file points at the dictionaries, which
hold the id -> name mapping.

Usage:
    python a7s2xml.py "Fatima Muntari.a7s"
    python a7s2xml.py save.a7s -o output --only meta,gamesetup
    python a7s2xml.py save.a7s --raw          # also write the raw .bin files
"""

import argparse
import os
import struct
import sys
import unicodedata
import zlib

RDA_MAGIC = b"Resource File V2.2"
RDA_FIRST_BLOCK_OFFSET = 0x310
RDA_DIR_ENTRY_SIZE = 560          # 260 wchar name + 5 x uint64
FILEDB_TRAILER_SIZE = 20
FILEDB_MAGIC = 0xFFFFFFFD
# Fixed ids that never appear in a dictionary: unnamed nodes used for list items.
RESERVED_TAGS = {1: "None"}
RESERVED_ATTRS = {0x8000: "None"}


# --------------------------------------------------------------------------
# 1) RDA container
# --------------------------------------------------------------------------

def read_rda(data):
    """Returns the files inside an RDA 2.2 archive as [(name, raw_bytes), ...]."""
    if not data.startswith(RDA_MAGIC):
        raise ValueError("RDA signature not found (expected 'Resource File V2.2')")

    files = []
    seen = set()
    offset = struct.unpack_from("<Q", data, RDA_FIRST_BLOCK_OFFSET)[0]

    while 0 < offset < len(data) and offset not in seen:
        seen.add(offset)
        flags, count = struct.unpack_from("<II", data, offset)
        dir_size, dir_raw_size, next_offset = struct.unpack_from("<QQQ", data, offset + 8)

        if flags & 2:
            raise ValueError("encrypted RDA block is not supported (flags=%d)" % flags)

        directory = data[offset - dir_size:offset]
        if flags & 1:
            directory = zlib.decompress(directory)
        if len(directory) != dir_raw_size:
            raise ValueError("directory size mismatch: %d != %d" % (len(directory), dir_raw_size))

        for i in range(count):
            entry = directory[i * RDA_DIR_ENTRY_SIZE:(i + 1) * RDA_DIR_ENTRY_SIZE]
            name = entry[:520].decode("utf-16-le", "replace").split("\x00")[0]
            file_offset, comp_size, _raw_size, _ts, _unk = struct.unpack_from("<QQQQQ", entry, 520)
            blob = data[file_offset:file_offset + comp_size]
            if flags & 1:
                blob = zlib.decompress(blob)
            files.append((name, blob))

        offset = next_offset

    return files


def decompress_stream(raw):
    """Decompresses consecutive zlib streams; an empty stream ends the data,
    followed by a uint32 holding the decompressed size."""
    pos = 0
    parts = []
    while pos < len(raw):
        obj = zlib.decompressobj()
        piece = obj.decompress(raw[pos:])
        piece += obj.flush()
        pos = len(raw) - len(obj.unused_data)
        if not piece:
            break                     # empty stream = end-of-data marker
        parts.append(piece)

    out = b"".join(parts)
    tail = raw[pos:]
    if len(tail) >= 4:
        expected = struct.unpack_from("<I", tail, 0)[0]
        if expected != len(out):
            raise ValueError("decompressed size mismatch: %d != %d" % (len(out), expected))
    return out


# --------------------------------------------------------------------------
# 2) FileDB binary format
# --------------------------------------------------------------------------

def _read_dictionary(data, offset):
    """[uint32 count][uint16 id x count][null terminated names] -> {id: name}"""
    count = struct.unpack_from("<I", data, offset)[0]
    ids = struct.unpack_from("<%dH" % count, data, offset + 4)
    pos = offset + 4 + count * 2
    names = {}
    for ident in ids:
        end = data.index(b"\x00", pos)
        names[ident] = data[pos:end].decode("utf-8", "replace")
        pos = end + 1
    return names


def parse_filedb_trailer(data):
    """Reads the dictionaries and the node count from the trailer."""
    if len(data) < FILEDB_TRAILER_SIZE:
        raise ValueError("file too short to contain a FileDB trailer")
    node_count, tag_off, attr_off, _hdr_size, magic = struct.unpack_from(
        "<IIIII", data, len(data) - FILEDB_TRAILER_SIZE)
    if magic != FILEDB_MAGIC:
        raise ValueError("FileDB signature not found (0x%08X)" % magic)
    tags = dict(RESERVED_TAGS)
    tags.update(_read_dictionary(data, tag_off))
    leaves = dict(RESERVED_ATTRS)
    leaves.update(_read_dictionary(data, attr_off))
    return node_count, tags, leaves, tag_off


# --------------------------------------------------------------------------
# 3) Interpreting leaf content
# --------------------------------------------------------------------------

_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def _is_text_like(text):
    """Is this text really readable: no control/unassigned/private characters.

    Every unicodedata category starting with 'C' (Cc, Cf, Cs, Co, Cn) is
    rejected, so binary data is not mistaken for text while accented and CJK
    names still decode correctly.
    """
    return bool(text) and all(unicodedata.category(c)[0] != "C" for c in text)


def _as_ascii(content):
    if len(content) < 2 or any(b not in _PRINTABLE for b in content):
        return None
    return content.decode("ascii")


def _as_utf16(content):
    """Decodes two byte aligned, fully printable UTF-16LE text.

    Decoding is strict: re-encoding the result must produce the exact same
    bytes, so writing the value to XML and packing it back is lossless.
    """
    if len(content) < 4 or len(content) % 2:
        return None
    try:
        text = content.decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    if not _is_text_like(text) or text.encode("utf-16-le") != content:
        return None
    return text


_SCALARS = {1: ("<B", "u8"), 2: ("<H", "u16"), 4: ("<i", "i32"), 8: ("<q", "i64")}


def decode_content(content):
    """Returns leaf content as (text, type_tag).

    1/2/4/8 byte payloads are almost always numbers and are read as such
    first; other sizes are tried as text and fall back to hex.
    (A 4 byte value may really be a float - the format carries no type info.)
    """
    if not content:
        return "", "empty"

    scalar = _SCALARS.get(len(content))
    if scalar:
        fmt, kind = scalar
        return str(struct.unpack(fmt, content)[0]), kind

    # ASCII first: real UTF-16 text contains zero bytes and therefore fails the
    # ASCII test anyway - this ordering keeps the two from being confused
    text = _as_ascii(content)
    if text is not None:
        return text, "str"
    text = _as_utf16(content)
    if text is not None:
        return text, "wstr"
    return content.hex(), "hex"


_ESCAPES = (("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"))


def xml_escape(text, quotes=False):
    """Escapes text for XML.

    \\t \\n \\r become numeric references: XML parsers normalise a raw \\r into
    \\n, so this keeps values byte identical when packing them back.
    """
    for old, new in _ESCAPES:
        text = text.replace(old, new)
    if quotes:
        text = text.replace('"', "&quot;")
    return "".join(c if c > "\x1f" else "&#%d;" % ord(c) for c in text)


def xml_name(name, fallback):
    """Produces a valid XML tag name."""
    if not name:
        return fallback
    cleaned = "".join(c if (c.isalnum() or c in "._-") else "_" for c in name)
    if not cleaned or not (cleaned[0].isalpha() or cleaned[0] == "_"):
        cleaned = "_" + cleaned
    return cleaned


def name_attr(original, cleaned):
    """Keeps the original name in n="..." when it had to be sanitised."""
    if original and original != cleaned:
        return ' n="%s"' % xml_escape(original, quotes=True)
    return ""


# --------------------------------------------------------------------------
# 4) FileDB -> XML (streaming, no tree is built in memory)
# --------------------------------------------------------------------------

def filedb_to_xml(data, out, root_name="Content", indent="  ", raw_hex=False):
    """Writes decompressed FileDB data to the `out` text stream as XML.

    Returns (node_count, warnings).
    """
    _node_count, tags, attrs, body_end = parse_filedb_trailer(data)

    out.write('<?xml version="1.0" encoding="utf-8"?>\n')
    out.write("<%s>\n" % root_name)

    stack = []          # names of the open tags
    pos = 0
    nodes = 0
    depth = 1

    while pos + 8 <= body_end:
        size, ident = struct.unpack_from("<IH", data, pos)
        pos += 8

        if ident == 0:                                   # closing tag
            if not stack:
                break                                    # root closed = end of document
            depth -= 1
            out.write("%s</%s>\n" % (indent * depth, stack.pop()))
            continue

        nodes += 1

        if ident & 0x8000:                               # leaf (node with content)
            content = data[pos:pos + size]
            pos += (size + 7) & ~7                       # content is padded to 8 bytes
            original = attrs.get(ident)
            name = xml_name(original, "attr_%04X" % ident)
            if raw_hex:
                text, kind = content.hex(), ("hex" if content else "empty")
            else:
                text, kind = decode_content(content)
            # t="..." is present on every leaf; the packer uses it to tell
            # leaves and container tags apart
            head = '%s%s' % (name_attr(original, name), ' t="%s"' % kind)
            if text:
                out.write("%s<%s%s>%s</%s>\n" % (indent * depth, name, head,
                                                 xml_escape(text), name))
            else:
                out.write("%s<%s%s />\n" % (indent * depth, name, head))
        else:                                            # opening tag
            original = tags.get(ident)
            name = xml_name(original, "tag_%04X" % ident)
            out.write("%s<%s%s>\n" % (indent * depth, name, name_attr(original, name)))
            stack.append(name)
            depth += 1

    warnings = []
    if stack:                                            # unclosed tags = broken parse
        warnings.append("%d tag(s) left unclosed" % len(stack))
    if pos != body_end:
        warnings.append("body not fully consumed (%d / %d bytes)" % (pos, body_end))

    while stack:                                          # still emit valid XML
        depth -= 1
        out.write("%s</%s>\n" % (indent * depth, stack.pop()))

    out.write("</%s>\n" % root_name)
    return nodes, warnings


# --------------------------------------------------------------------------
# 5) Command line
# --------------------------------------------------------------------------

def convert(path, outdir, only=None, write_raw=False, raw_hex=False, quiet=False):
    with open(path, "rb") as handle:
        data = handle.read()

    os.makedirs(outdir, exist_ok=True)
    results = []

    for name, blob in read_rda(data):
        stem = os.path.splitext(name)[0]
        if only and stem not in only:
            continue

        raw = decompress_stream(blob)
        if write_raw:
            with open(os.path.join(outdir, stem + ".bin"), "wb") as handle:
                handle.write(raw)

        target = os.path.join(outdir, stem + ".xml")
        with open(target, "w", encoding="utf-8", newline="\n") as handle:
            nodes, warnings = filedb_to_xml(raw, handle, root_name=xml_name(stem, "Content"),
                                            raw_hex=raw_hex)

        results.append((name, len(blob), len(raw), target, nodes, warnings))
        if not quiet:
            print("%-14s %9d B packed -> %10d B raw -> %-14s %8d nodes"
                  % (name, len(blob), len(raw), os.path.basename(target), nodes))
            for warning in warnings:
                print("   warning: %s" % warning)

    return results


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Convert an Anno 1800 .a7s save game to XML.")
    parser.add_argument("input", help="input .a7s file")
    parser.add_argument("-o", "--outdir", default=None,
                        help="output folder (default: <filename>_xml)")
    parser.add_argument("--only", default=None,
                        help="only these sections, comma separated: meta,header,gamesetup,data")
    parser.add_argument("--raw", action="store_true",
                        help="also write the decompressed binary FileDB data as .bin")
    parser.add_argument("--hex", action="store_true", dest="raw_hex",
                        help="write every leaf value as hex without interpreting it")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress output")
    args = parser.parse_args(argv)

    outdir = args.outdir or os.path.splitext(args.input)[0] + "_xml"
    only = {s.strip() for s in args.only.split(",")} if args.only else None

    try:
        convert(args.input, outdir, only=only, write_raw=args.raw,
                raw_hex=args.raw_hex, quiet=args.quiet)
    except (ValueError, OSError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1

    if not args.quiet:
        print("\ndone -> %s" % os.path.abspath(outdir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
