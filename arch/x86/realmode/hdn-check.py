#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check the native ELF32 real-mode/long-mode boundary before blob admission.

The BIOS and its 16-bit execution environment are a foreign trust domain.
This check does not claim to instrument BIOS calls or real-mode C returns.
It closes that domain's 32/64-bit launch program: exact code, descriptors,
page-separated authority, and the relocation stream which the kernel copies.
The ordinary kernel's objtool gate checks the receiving startup/reboot roots.
"""
import struct
import sys
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unpack(fmt, data, offset=0):
    size = struct.calcsize(fmt)
    require(0 <= offset <= len(data) - size, "truncated ELF/relocation input")
    return struct.unpack_from(fmt, data, offset)


class Image:
    def __init__(self, path, reloc_path):
        self.data = Path(path).read_bytes()
        require(self.data[:7] == b"\x7fELF\x01\x01\x01", "expected little-endian ELF32")
        h = unpack("<HHIIIIIHHHHHH", self.data, 16)
        require(h[0:3] == (2, 3, 1) and h[7] == 52 and h[10] == 40,
                "expected i386 executable with standard ELF headers")
        require(0 < h[11] < 0xff00 and h[12] < h[11], "unsupported section numbering")
        require(not h[9] or h[8] == 32, "unexpected program header size")
        for n in range(h[9]):
            ph = unpack("<IIIIIIII", self.data, h[4] + n * 32)
            if ph[0] == 1:
                require(ph[2] == ph[3] and ph[4] <= ph[5], "nonidentity load segment")
        self.sections = [unpack("<IIIIIIIIII", self.data, h[5] + n * 40)
                         for n in range(h[11])]
        names = self.section_data(h[12])
        self.section_names = [self.string(names, s[0]) for s in self.sections]
        require(len(set(self.section_names)) == len(self.section_names), "duplicate sections")
        self.symbols = {}
        self.tables = {}
        self.relocations = {}
        self.physical = set()
        self.segments = set()
        intervals = []
        for n, s in enumerate(self.sections):
            if s[2] & 2 and s[5]:
                require(s[3] + s[5] <= 0x10000, "real-mode image exceeds segment")
                require(not (s[2] & 1 and s[2] & 4), "writable executable section")
                intervals.append((s[3], s[3] + s[5]))
            if s[1] != 2:
                continue
            require(s[9] == 16 and s[5] % 16 == 0, "malformed symbol table")
            strings = self.section_data(s[6])
            table = []
            for p in range(0, s[5], 16):
                raw = unpack("<IIIBBH", self.section_data(n), p)
                name = self.string(strings, raw[0])
                symbol = (name, raw[1], raw[2], raw[3], raw[5])
                table.append(symbol)
                if name and raw[5]:
                    self.symbols.setdefault(name, []).append(symbol)
            self.tables[n] = table
        intervals.sort()
        require(all(a[1] <= b[0] for a, b in zip(intervals, intervals[1:])),
                "overlapping allocated sections")
        for n, s in enumerate(self.sections):
            if s[1] not in (4, 9):
                continue
            require(s[1] == 9 and s[9] == 8 and s[5] % 8 == 0, "unexpected relocation format")
            require(s[6] in self.tables and s[7] < len(self.sections), "bad relocation section")
            target = self.sections[s[7]]
            if not target[2] & 2:
                continue
            for p in range(0, s[5], 8):
                address, info = unpack("<II", self.section_data(n), p)
                kind, index = info & 255, info >> 8
                if kind == 0:
                    continue
                table = self.tables[s[6]]
                require(index < len(table) and table[index][4], "undefined relocation target")
                name = table[index][0]
                width = {1: 4, 2: 4, 4: 4, 20: 2, 21: 2, 23: 1}.get(kind)
                require(width and target[3] <= address <= target[3] + target[5] - width,
                        "unsupported or out-of-range relocation")
                require(not any(x in self.relocations for x in range(address, address + width)),
                        "overlapping relocations")
                for x in range(address, address + width):
                    self.relocations[x] = (address, kind, name)
                if kind == 1 and name.startswith("pa_"):
                    self.physical.add(address)
                elif kind == 20 and name == "real_mode_seg":
                    self.segments.add(address)
                else:
                    require(not (name.startswith("pa_") or name == "real_mode_seg"),
                            "invalid relocation of a physical/segment identity")
        raw = Path(reloc_path).read_bytes()
        cursor = 0
        for expected, width in ((self.segments, 2), (self.physical, 4)):
            count, = unpack("<I", raw, cursor)
            cursor += 4
            require(count <= len(raw) // 4, "oversized relocation count")
            actual = [unpack("<I", raw, cursor + i * 4)[0] for i in range(count)]
            cursor += count * 4
            require(len(set(actual)) == count and set(actual) == expected,
                    "blob relocation stream differs from ELF")
            for address in actual:
                self.at(address, width)
        require(cursor == len(raw), "trailing relocation data")

    @staticmethod
    def string(data, offset):
        require(0 <= offset < len(data), "invalid string offset")
        end = data.find(b"\0", offset)
        require(end >= 0, "unterminated string")
        return data[offset:end].decode("ascii")

    def section_data(self, index):
        require(0 <= index < len(self.sections), "invalid section index")
        s = self.sections[index]
        if s[1] == 8:
            require(s[5] <= 0x10000, "oversized NOBITS section")
            return bytes(s[5])
        require(s[4] <= len(self.data) and s[5] <= len(self.data) - s[4], "truncated section")
        return self.data[s[4]:s[4] + s[5]]

    def symbol(self, name):
        require(name in self.symbols, "missing symbol: " + name)
        require(len(self.symbols[name]) == 1, "ambiguous symbol: " + name)
        return self.symbols[name][0]

    def value(self, name):
        return self.symbol(name)[1]

    def at(self, address, size):
        for i, s in enumerate(self.sections):
            if s[2] & 2 and s[3] <= address and address + size <= s[3] + s[5]:
                return self.section_data(i)[address - s[3]:address - s[3] + size]
        raise ValueError("address outside image")

    def object(self, name, expected, physical=()):
        s = self.symbol(name)
        require(s[2] == len(expected) and self.at(s[1], s[2]) == expected,
                "invalid data object: " + name)
        require({p - s[1] for p in self.physical if s[1] <= p < s[1] + s[2]} == set(physical) and
                not any(s[1] <= p < s[1] + s[2] for p in self.segments),
                "invalid authority relocations: " + name)

    def binary(self, path):
        sections = [(i, s) for i, s in enumerate(self.sections) if s[2] & 2 and s[1] != 8 and s[5]]
        require(sections and min(s[3] for _, s in sections) == 0, "binary does not start with header")
        blob = bytearray(max(s[3] + s[5] for _, s in sections))
        for i, s in sections:
            blob[s[3]:s[3] + s[5]] = self.section_data(i)
        require(Path(path).read_bytes() == blob, "raw blob differs from checked ELF")


class Program:
    def __init__(self, image, name):
        self.image, self.name = image, name
        s = image.symbol(name)
        require(0 < s[4] < len(image.sections) and image.sections[s[4]][2] & 4 and s[2],
                "missing executable extent: " + name)
        self.start, self.end, self.pos = s[1], s[1] + s[2], s[1]
        self.labels, self.edges = {}, []
        self.allowed_physical = set()

    def take(self, size):
        require(self.pos + size <= self.end, "truncated program: " + self.name)
        result = self.image.at(self.pos, size)
        self.pos += size
        return result

    def literal(self, value):
        data = bytes.fromhex(value)
        start = self.pos
        require(self.take(len(data)) == data, "unexpected instruction: " + self.name)
        require(not any(x in self.image.relocations for x in range(start, self.pos)),
                "relocated opcode or constant: " + self.name)

    def reference(self, prefix, name, offset=0, relative=False):
        self.literal(prefix)
        address = self.pos
        value, = unpack("<I", self.take(4))
        target = self.image.value(name) + offset
        require(value == ((target - self.pos) & 0xffffffff if relative else target),
                "wrong reference: " + self.name + " -> " + name)
        require(not any(x in self.image.segments for x in range(address, self.pos)),
                "segment relocation in transition program")
        if not relative and name.startswith("pa_"):
            require(address in self.image.physical, "missing physical relocation")
            self.allowed_physical.add(address)
        else:
            require(not any(x in self.image.physical for x in range(address, self.pos)),
                    "unexpected physical relocation")

    def label(self, name):
        require(name not in self.labels, "duplicate program label")
        self.labels[name] = self.pos

    def branch(self, opcode, label):
        first = self.take(1)[0]
        if first == opcode:
            delta, = unpack("<b", self.take(1))
        elif first == 0x0f and 0x70 <= opcode <= 0x7f:
            require(self.take(1)[0] == opcode + 0x10, "wrong long branch")
            delta, = unpack("<i", self.take(4))
        elif first == 0xe9 and opcode == 0xeb:
            delta, = unpack("<i", self.take(4))
        else:
            raise ValueError("wrong branch: " + self.name)
        self.edges.append((self.pos + delta, label))

    def finish(self):
        require(self.pos == self.end, "uncovered transition instructions: " + self.name)
        require(all(label in self.labels and self.labels[label] == target
                    for target, label in self.edges), "wrong branch destination: " + self.name)
        require({p for p in self.image.physical if self.start <= p < self.end} == self.allowed_physical,
                "unadmitted transition relocation")
        require(not any(self.start <= p < self.end for p in self.image.segments),
                "segment relocation in transition program")


def lock_and_stack(p):
    p.label("lock")
    p.reference("f0 0f ba 2d", "pa_tr_lock")
    p.literal("00")
    p.branch(0x73, "locked")
    p.literal("f3 90")
    p.branch(0xeb, "lock")
    p.label("locked")
    p.reference("bc", "rm_stack_end")


def padding(data, bits):
    # GAS can choose any of these architecturally inert alignment NOPs.
    nops = [bytes.fromhex(s) for s in (
        "90", "66 90", "0f 1f 00", "0f 1f 40 00", "0f 1f 44 00 00",
        "66 0f 1f 44 00 00", "0f 1f 80 00 00 00 00",
        "0f 1f 84 00 00 00 00 00", "66 0f 1f 84 00 00 00 00 00")]
    if bits == 64:
        # GAS -mtune=generic64 also aligns with a CS-prefixed 64-bit LEA.
        # This exact base/index/displacement preserves RSI and touches no memory.
        nops += [bytes.fromhex("2e 48 8d b4 26 00 00 00 00")]
    if bits == 32:
        nops += [bytes.fromhex(s) for s in (
            "89 f6", "8d 76 00", "8d 74 26 00", "8d b6 00 00 00 00",
            "8d b4 26 00 00 00 00", "8d bc 27 00 00 00 00")]
    while data:
        match = next((n for n in reversed(nops) if data.startswith(n)), None)
        require(match is not None, "uncovered transition code")
        data = data[len(match):]


def cover_section(image, section, names):
    require(section in image.section_names, "missing transition section")
    sec = image.sections[image.section_names.index(section)]
    regions = sorted((image.value(n), image.value(n) + image.symbol(n)[2]) for n in names)
    cursor = sec[3]
    for first, last in regions:
        require(cursor <= first < last <= sec[3] + sec[5], "bad transition extents")
        padding(image.at(cursor, first - cursor), 32 if section == ".text32" else 64)
        require(not any(x in image.relocations for x in range(cursor, first)), "relocated padding")
        cursor = last
    padding(image.at(cursor, sec[3] + sec[5] - cursor), 32 if section == ".text32" else 64)
    require(not any(x in image.relocations for x in range(cursor, sec[3] + sec[5])), "relocated padding")


def check(image):
    require("sev_es_trampoline_start" not in image.symbols, "confidential-memory transition is not native RAP")
    for name in ("trampoline_header", "trampoline_pgd", "tr_lock"):
        require(image.value(name) % 4096 == 0, "authority is not page-separated: " + name)
    authority = [image.value(n) // 4096 for n in ("trampoline_header", "trampoline_pgd", "tr_lock")]
    require(len(set(authority)) == len(authority), "mutable lock aliases launch authority")
    image.object("trampoline_header", bytes(24) + struct.pack("<I", image.value("pa_tr_lock")), (24,))
    require(image.value("tr_start") == image.value("trampoline_header") and
            image.value("tr_efer") == image.value("tr_start") + 8 and
            image.value("tr_cr4") == image.value("tr_start") + 16 and
            image.value("tr_flags") == image.value("tr_start") + 20,
            "launch field layout changed")
    image.object("trampoline_pgd", bytes(4096))
    image.object("tr_idt", bytes(10))
    image.object("tr_gdt", struct.pack("<HIHQQQ", 31, image.value("pa_tr_gdt"), 0,
                                     0x00cf9b000000ffff, 0x00af9b000000ffff, 0x00cf93000000ffff), (2,))
    image.object("tr_gdt64", struct.pack("<HII", 31, image.value("pa_tr_gdt"), 0), (2,))
    image.object("tr_compat", struct.pack("<IH", image.value("pa_trampoline_compat"), 8), (0,))
    require(image.value("pa_trampoline_compat") == image.value("pa_pa_trampoline_compat"),
            "compatibility entry alias differs")

    p = Program(image, "startup_64")
    p.reference("ff 25", "tr_start", relative=True)
    p.finish()

    p = Program(image, "trampoline_start64")
    p.reference("0f 01 1d", "tr_idt", relative=True)
    p.reference("0f 01 15", "tr_gdt64", relative=True)
    p.literal("0f 20 e0")
    p.reference("33 05", "tr_cr4", relative=True)
    p.literal("a9 00 10 00 00")
    p.branch(0x75, "switch")
    p.label("lock")
    p.reference("f0 0f ba 2d", "tr_lock", offset=-1, relative=True)
    p.literal("00")
    p.branch(0x73, "locked")
    p.literal("f3 90")
    p.branch(0xeb, "lock")
    p.label("locked")
    p.reference("bc", "rm_stack_end")
    p.literal("66 ba 18 00 8e d2")
    p.reference("81 c4", "pa_real_mode_base")
    p.literal("8e da 8e c2 8e e2 8e ea")
    p.reference("b8", "pa_trampoline_pgd")
    p.literal("0f 22 d8 6a 10")
    p.reference("ff 35", "tr_start", relative=True)
    p.literal("48 cb")
    p.label("switch")
    p.reference("ff 2d", "tr_compat", relative=True)
    p.finish()

    p = Program(image, "startup_32")
    p.literal("8e d2")
    p.reference("81 c4", "pa_real_mode_base")
    p.literal("8e da 8e c2 8e e2 8e ea")
    p.reference("0f ba 25", "pa_tr_flags")
    p.literal("00")
    p.branch(0x73, "sme_done")
    p.literal("b9 10 00 01 c0 0f 32 0f ba e8 17")
    p.branch(0x72, "sme_done")
    p.literal("0f 30")
    p.label("sme_done")
    p.reference("a1", "pa_tr_cr4")
    p.literal("0f 22 e0")
    p.reference("b8", "pa_trampoline_pgd")
    p.literal("0f 22 d8 b9 80 00 00 c0 0f 32")
    p.reference("3b 05", "pa_tr_efer")
    p.branch(0x75, "efer_write")
    p.reference("3b 15", "pa_tr_efer", offset=4)
    p.branch(0x74, "efer_done")
    p.label("efer_write")
    p.reference("a1", "pa_tr_efer")
    p.reference("8b 15", "pa_tr_efer", offset=4)
    p.literal("0f 30")
    p.label("efer_done")
    p.literal("b8 33 00 05 80 0f 22 c0")
    p.reference("ea", "pa_startup_64")
    p.literal("10 00")
    p.finish()

    p = Program(image, "pa_trampoline_compat")
    lock_and_stack(p)
    p.literal("66 ba 18 00 b8 33 00 05 00 0f 22 c0")
    p.reference("ea", "pa_startup_32")
    p.literal("08 00")
    p.finish()

    p = Program(image, "machine_real_restart_asm")
    p.literal("b8 18 00 00 00 8e d8")
    p.reference("0f 01 15", "pa_tr_gdt")
    p.literal("0f 20 c0 25 ff ff ff 7f 0f 22 c0")
    p.reference("ea", "pa_machine_real_restart_paging_off")
    p.literal("08 00")
    require(p.pos == image.value("machine_real_restart_paging_off"), "wrong paging-off continuation")
    p.literal("31 c0 31 d2 b9 80 00 00 c0 0f 30 89 f8")
    p.reference("0f 01 1d", "pa_machine_real_restart_idt")
    p.reference("0f 01 15", "pa_machine_real_restart_gdt")
    p.literal("b9 10 00 00 00 8e d9 8e c1 8e e1 8e e9 8e d1 66 ea")
    target, = unpack("<H", p.take(2))
    require(target == image.value("machine_real_restart_asm16"), "wrong real-mode restart continuation")
    p.literal("08 00")
    p.finish()
    image.object("machine_real_restart_idt", struct.pack("<HI", 0xffff, 0))
    image.object("machine_real_restart_gdt", struct.pack("<HIHHIHQ", 0xffff,
                 image.value("pa_machine_real_restart_gdt"), 0, 0xffff,
                 0x9b000000 + image.value("pa_real_mode_base"), 0, 0x000093000100ffff), (2, 10))

    header = ["pa_text_start", "pa_ro_end", "pa_trampoline_start", "pa_trampoline_header",
              "pa_trampoline_start64", "pa_trampoline_pgd"]
    if "wakeup_start" in image.symbols:
        header += ["pa_wakeup_start", "pa_wakeup_header"]
        require(image.value("wakeup_header") % 4096 == 0 and
                image.value("wakeup_header") // 4096 not in authority,
                "wakeup authority shares mutable data")
    header += ["pa_machine_real_restart_asm"]
    image.object("real_mode_header", struct.pack("<" + "I" * (len(header) + 1),
                 *(image.value(n) for n in header), 8), range(0, len(header) * 4, 4))
    for name in ("real_mode_header", "tr_idt", "tr_gdt", "tr_gdt64", "tr_compat",
                 "machine_real_restart_idt", "machine_real_restart_gdt"):
        s = image.symbol(name)
        require(0 < s[4] < len(image.sections) and image.sections[s[4]][2] & 2 and
                not image.sections[s[4]][2] & 5 and
                s[1] + s[2] <= image.value("pa_text_start"),
                "descriptor outside sealed read-only prefix: " + name)
    require(image.value("pa_text_start") % 4096 == 0 and
            image.value("trampoline_header") >= ((image.value("pa_ro_end") + 4095) & ~4095),
            "launch data overlaps executable pages")

    # Every protected/long-mode byte belongs to a checked program or padding.
    cover_section(image, ".text32", ("startup_32", "pa_trampoline_compat", "machine_real_restart_asm"))
    cover_section(image, ".text64", ("startup_64", "trampoline_start64"))


if __name__ == "__main__":
    try:
        require(len(sys.argv) in (3, 4), "usage: hdn-check.py realmode.elf realmode.relocs [realmode.bin]")
        image = Image(sys.argv[1], sys.argv[2])
        check(image)
        if len(sys.argv) == 4:
            image.binary(sys.argv[3])
    except (ValueError, OSError, UnicodeError, struct.error) as error:
        sys.exit("HDN real-mode boundary rejected: " + str(error))
