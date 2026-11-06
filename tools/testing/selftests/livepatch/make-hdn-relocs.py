#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Convert the HDN fixture's local stand-in relocations before module signing."""
import argparse
import pathlib
import struct

EH = struct.Struct('<16sHHIQQQIHHHHHH')
SH = struct.Struct('<IIQQQQIIQQ')
SY = struct.Struct('<IBBHQQ')
RE = struct.Struct('<QQq')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=pathlib.Path)
    parser.add_argument('output', type=pathlib.Path)
    parser.add_argument('--mode', choices=['good', 'missing', 'bounds', 'overlap', 'metadata'], default='good')
    args = parser.parse_args()
    raw = args.input.read_bytes()
    if raw.endswith(b'~Module signature appended~\n'):
        parser.error('rewrite the unsigned fixture, then sign the output')
    h = list(EH.unpack_from(raw))
    if h[0][:6] != b'\x7fELF\x02\x01' or h[1:3] != [1, 62] or h[10] or h[11] != SH.size:
        parser.error('expected an ELF64 little-endian x86-64 relocatable module')
    sections = [list(SH.unpack_from(raw, h[6] + i * SH.size)) for i in range(h[12])]
    blobs = [bytearray(raw[s[4]:s[4] + s[5]]) if s[1] != 8 else bytearray() for s in sections]
    shstr = h[13]

    def name(index):
        pos = sections[index][0]
        return bytes(blobs[shstr][pos:]).split(b'\0', 1)[0].decode()

    symtabs = [i for i, s in enumerate(sections) if s[1] == 2]
    if len(symtabs) != 1:
        parser.error('expected one symbol table')
    symtab = symtabs[0]
    strtab = sections[symtab][6]
    symbols = [list(SY.unpack_from(blobs[symtab], i)) for i in range(0, len(blobs[symtab]), SY.size)]
    bindings = [i for i, s in enumerate(symbols)
                if bytes(blobs[strtab][s[0]:]).split(b'\0', 1)[0] == b'hdn_klp_binding']
    if len(bindings) != 1:
        parser.error('fixture stand-in symbol is missing or ambiguous')
    binding = bindings[0]
    found = 0
    additions = []
    for index, sec in enumerate(sections):
        if sec[1] != 4 or sec[6] != symtab:
            continue
        keep, selected = bytearray(), bytearray()
        for offset in range(0, len(blobs[index]), RE.size):
            r = list(RE.unpack_from(blobs[index], offset))
            if r[1] >> 32 != binding:
                keep.extend(RE.pack(*r))
                continue
            if r[1] & 0xffffffff != 1 or not name(sec[7]).startswith(('.data', '.rodata')):
                parser.error('stand-in has an unexpected non-data or non-64-bit relocation')
            found += 1
            if args.mode == 'bounds' and found == 1:
                r[0] = sections[sec[7]][5] - 4
            selected.extend(RE.pack(*r))
            if args.mode == 'overlap' and found == 1:
                selected.extend(RE.pack(*r))
        if not selected:
            continue
        blobs[index] = keep
        target = sec[7]
        if args.mode == 'metadata' and not additions:
            candidates = [i for i in range(len(sections)) if name(i) == '.hdn.rap.types']
            if len(candidates) != 1:
                parser.error('metadata mode requires a RAP-instrumented fixture')
            target = candidates[0]
            first = list(RE.unpack_from(selected))
            first[0] = 0
            selected[:RE.size] = RE.pack(*first)
        section_name = '.klp.rela.test_hdn_klp_target.' + name(target)
        name_offset = len(blobs[shstr])
        blobs[shstr].extend(section_name.encode() + b'\0')
        additions.append(([name_offset, 4, 0x100002, 0, 0, len(selected), symtab, target, 8, RE.size], selected))
    if found != 2:
        parser.error(f'expected exactly two stand-in data relocations, found {found}')
    symbol_name = '.klp.sym.test_hdn_klp_target.' + ('hdn_klp_absent' if args.mode == 'missing' else 'hdn_klp_secret') + ',0'
    symbols[binding][0] = len(blobs[strtab])
    symbols[binding][3] = 0xff20
    symbols[binding][4] = 0
    blobs[strtab].extend(symbol_name.encode() + b'\0')
    blobs[symtab] = bytearray().join(SY.pack(*s) for s in symbols)
    for sec, blob in additions:
        sections.append(sec)
        blobs.append(blob)
    result = bytearray(EH.size)
    for index, (sec, blob) in enumerate(zip(sections, blobs)):
        if index == 0:
            continue
        alignment = sec[8] or 1
        result.extend(b'\0' * (-len(result) % alignment))
        sec[4] = len(result)
        if sec[1] != 8:
            sec[5] = len(blob)
            result.extend(blob)
    result.extend(b'\0' * (-len(result) % 8))
    h[6], h[12] = len(result), len(sections)
    result.extend(b''.join(SH.pack(*s) for s in sections))
    result[:EH.size] = EH.pack(*h)
    args.output.write_bytes(result)


if __name__ == '__main__':
    main()
