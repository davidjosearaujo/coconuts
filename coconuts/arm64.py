"""Reads the XXTEA key *and* its signature straight out of the arm64 engine library.

What a human does in Ghidra: find AppDelegate::applicationDidFinishLaunching, spot the call through
the LuaStack vtable, and read its arguments --

    (**(code **)(*stack + 0xe8))(stack, "cocos2d_lua_js", 0xe, "LJ", 2);
                                        key              len   sign len

That call compiles to a fixed, recognisable shape on arm64, so it can be read directly:

    adrp x1, <page> ; add x1, x1, #<off>   key pointer
    mov  w2, #14                           key length
    adrp x3, <page> ; add x3, x3, #<off>   signature pointer
    mov  w4, #2                            signature length
    ldr  x5, [x8, #0xe8] ; blr x5          the virtual call

The string tiers in statickeys.py collect every literal in that function and trial-decrypt them
one by one, which finds the key but never learns which literal was the signature. This recovers
the pair, so the signature doesn't have to be guessed from a common prefix across ciphertexts.

Deliberately not radare2: this is a few instruction forms on a fixed-width ISA, and it has to work
when r2 isn't installed. Matching is on the *shape* of the arguments -- two string pointers whose
lengths are passed alongside them -- rather than on the 0xe8 offset, which varies by Cocos version.
Every result is still trial-decrypted by the caller, so a wrong match costs nothing.
"""

from __future__ import annotations

import struct
from typing import NamedTuple

from .log import slog

EM_AARCH64 = 183
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHT_SYMTAB = 2
SHT_DYNSYM = 11

MAX_KEY_LEN = 64
MAX_SIGN_LEN = 32
WINDOW = 64            # instructions of register history kept before a call
MAX_SCAN_INSNS = 4_000_000   # ~16 MB of code; a bound so a huge or corrupt lib can't hang the run

VTABLE_OFFSETS = (0xE8,)  # LuaStack::setXXTEAKeyAndSign in the builds seen so far; a hint only


class KeyAndSign(NamedTuple):
    key: bytes
    sign: bytes
    where: str  # for logging: the address and how it was found


class _Elf:
    """Just enough ELF64 to find functions and read strings by virtual address."""

    def __init__(self, data: bytes):
        self.data = data
        self.ok = False
        if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            return  # not a 64-bit little-endian ELF
        if struct.unpack_from("<H", data, 18)[0] != EM_AARCH64:
            return
        shoff = struct.unpack_from("<Q", data, 0x28)[0]
        shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)
        if shoff == 0 or shnum == 0 or shoff + shnum * shentsize > len(data):
            return
        self.sections = []
        for i in range(shnum):
            name, stype, flags, addr, off, size, link, info, align, entsize = struct.unpack_from(
                "<IIQQQQIIQQ", data, shoff + i * shentsize)
            self.sections.append(dict(name=name, type=stype, flags=flags, addr=addr, off=off,
                                      size=size, link=link, entsize=entsize))
        self.ok = True

    def read_at_vaddr(self, vaddr: int, length: int) -> bytes | None:
        for s in self.sections:
            if s["flags"] & SHF_ALLOC and s["type"] != 8 and s["addr"] <= vaddr < s["addr"] + s["size"]:
                start = s["off"] + (vaddr - s["addr"])
                return self.data[start:start + length]
        return None

    def cstring_at(self, vaddr: int, limit: int) -> bytes | None:
        raw = self.read_at_vaddr(vaddr, limit + 1)
        if not raw:
            return None
        end = raw.find(b"\0")
        return None if end <= 0 else raw[:end]

    def exec_sections(self) -> list[dict]:
        return [s for s in self.sections
                if s["flags"] & SHF_EXECINSTR and s["type"] == 1 and s["size"]]

    def functions_named(self, needle: str) -> list[tuple[int, int]]:
        """(vaddr, size) of symbols whose name contains `needle`."""
        out = []
        for s in self.sections:
            if s["type"] not in (SHT_SYMTAB, SHT_DYNSYM) or not s["entsize"]:
                continue
            strtab = self.sections[s["link"]] if s["link"] < len(self.sections) else None
            if strtab is None:
                continue
            for off in range(0, s["size"], s["entsize"]):
                try:
                    st_name, _info, _other, _shndx, value, size = struct.unpack_from(
                        "<IBBHQQ", self.data, s["off"] + off)
                except struct.error:
                    break
                if not st_name or not value:
                    continue
                base = strtab["off"] + st_name
                end = self.data.find(b"\0", base)
                if end < 0:
                    continue
                if needle in self.data[base:end].decode("utf-8", "replace"):
                    out.append((value, size))
        return out


def _decode_into(regs: dict[int, int], word: int, pc: int) -> str | None:
    """Applies one instruction to the tracked register state. Returns 'call' at a call."""
    if (word & 0x9F000000) == 0x90000000:                      # ADRP Xd, page
        imm = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3)
        if imm & (1 << 20):
            imm -= 1 << 21
        regs[word & 31] = (pc & ~0xFFF) + (imm << 12)
        return None
    if (word & 0xFF000000) == 0x91000000:                      # ADD Xd, Xn, #imm
        rd, rn = word & 31, (word >> 5) & 31
        imm = (word >> 10) & 0xFFF
        if (word >> 22) & 1:
            imm <<= 12
        if rn in regs:
            regs[rd] = regs[rn] + imm
        else:
            regs.pop(rd, None)
        return None
    if (word & 0x7F800000) == 0x52800000:                      # MOVZ Wd/Xd, #imm16 LSL hw
        hw = (word >> 21) & 3
        regs[word & 31] = ((word >> 5) & 0xFFFF) << (hw * 16)
        return None
    if (word & 0x7FE0FFE0) == 0x2A0003E0:                      # MOV Wd, Wm (ORR with WZR)
        rd, rm = word & 31, (word >> 16) & 31
        if rm == 31:
            regs[rd] = 0
        elif rm in regs:
            regs[rd] = regs[rm]
        else:
            regs.pop(rd, None)
        return None
    if (word & 0xFFFFFC1F) == 0xD63F0000:                      # BLR Xn
        return "call"
    if (word & 0xFC000000) == 0x94000000:                      # BL <label>
        return "call"
    if (word & 0xFFFFFC1F) == 0xD65F0000:                      # RET
        return "ret"
    return None


def _matches_at_call(elf: _Elf, regs: dict[int, int], vtable_off: int | None,
                     pc: int) -> list[KeyAndSign]:
    """A call is interesting when x1/x3 are strings whose lengths are in w2/w4."""
    out: list[KeyAndSign] = []
    for first, second in ((1, 3), (3, 1)):  # canonical (key, sign) first, then the reverse
        pair = []
        for ptr_reg, len_reg, cap in ((first, first + 1, MAX_KEY_LEN),
                                      (second, second + 1, MAX_SIGN_LEN)):
            if ptr_reg not in regs or len_reg not in regs:
                break
            declared = regs[len_reg]
            if not 1 <= declared <= cap:
                break
            text = elf.cstring_at(regs[ptr_reg], cap)
            # The length passed to the call must be the string's own length: that coincidence is
            # what makes this a key/signature call rather than any other two-string call.
            if text is None or len(text) != declared or not text.isascii():
                break
            pair.append(text)
        if len(pair) == 2 and pair[0] != pair[1]:
            how = f"{pc:#x}" + (f" via vtable+{vtable_off:#x}" if vtable_off is not None else "")
            out.append(KeyAndSign(pair[0], pair[1], how))
    return out


def _scan_range(elf: _Elf, vaddr: int, size: int, budget: list[int]) -> list[KeyAndSign]:
    code = elf.read_at_vaddr(vaddr, size)
    if not code:
        return []
    regs: dict[int, int] = {}
    vtable_off: int | None = None
    since_vtable = 0
    found: list[KeyAndSign] = []
    for i in range(0, len(code) - 3, 4):
        if budget[0] <= 0:
            break
        budget[0] -= 1
        word = struct.unpack_from("<I", code, i)[0]
        pc = vaddr + i

        if (word & 0xFFC00000) == 0xF9400000:        # LDR Xt, [Xn, #imm] -- maybe a vtable slot
            off = ((word >> 10) & 0xFFF) * 8
            if off in VTABLE_OFFSETS:
                vtable_off, since_vtable = off, 0
            continue

        event = _decode_into(regs, word, pc)
        if event == "call":
            found.extend(_matches_at_call(elf, regs, vtable_off if since_vtable < 8 else None, pc))
            # AAPCS: a call clobbers x0-x17, so the tracked argument registers are dead after it.
            for r in range(0, 18):
                regs.pop(r, None)
            vtable_off = None
        elif event == "ret":
            regs.clear()
            vtable_off = None
        if vtable_off is not None:
            since_vtable += 1
            if since_vtable > WINDOW:
                vtable_off = None
    return found


def find_key_and_sign(lib_path: str) -> list[KeyAndSign]:
    """Candidate (key, signature) pairs read from the engine library, best first.

    Never raises: a library that can't be parsed simply yields nothing and the string tiers in
    statickeys.py carry on as before.
    """
    try:
        with open(lib_path, "rb") as f:
            data = f.read()
    except OSError as e:
        slog.debug("arm64 key scan: %s", e)
        return []

    elf = _Elf(data)
    if not elf.ok:
        slog.debug("arm64 key scan: %s isn't a 64-bit little-endian aarch64 ELF", lib_path)
        return []

    budget = [MAX_SCAN_INSNS]
    results: list[KeyAndSign] = []

    # The call lives in applicationDidFinishLaunching, so look there first and cheaply.
    targets = elf.functions_named("applicationDidFinishLaunching")
    for vaddr, size in targets:
        results.extend(_scan_range(elf, vaddr, size or 4096, budget))

    # Stripped library, or the symbol didn't lead anywhere: sweep the executable sections.
    if not results:
        for section in elf.exec_sections():
            results.extend(_scan_range(elf, section["addr"], section["size"], budget))

    # A match through a known vtable slot is likelier to be the real call than a bare one.
    results.sort(key=lambda r: ("vtable" not in r.where,))
    unique: dict[tuple[bytes, bytes], KeyAndSign] = {}
    for r in results:
        unique.setdefault((r.key, r.sign), r)
    if unique:
        slog.debug("arm64 key scan: %d candidate pair(s) from %s", len(unique), lib_path)
    return list(unique.values())
