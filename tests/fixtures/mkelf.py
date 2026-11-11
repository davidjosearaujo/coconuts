"""Builds a minimal aarch64 ET_DYN ELF containing a Cocos-shaped setXXTEAKeyAndSign call.

There is no aarch64 linker on this host, so the fixture is assembled directly. That is an
advantage for testing anyway: the vtable offset, argument order and register allocation can all be
varied to mimic different Cocos builds.
"""

from __future__ import annotations

import struct

# --- aarch64 instruction encoders ------------------------------------------------------------


def adrp(rd: int, pc: int, target: int) -> int:
    imm = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
    imm &= (1 << 21) - 1
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd


def add_imm(rd: int, rn: int, imm12: int) -> int:
    return 0x91000000 | ((imm12 & 0xFFF) << 10) | (rn << 5) | rd


def movz_w(rd: int, imm16: int) -> int:
    return 0x52800000 | ((imm16 & 0xFFFF) << 5) | rd


def ldr_x(rt: int, rn: int, off: int) -> int:
    return 0xF9400000 | (((off // 8) & 0xFFF) << 10) | (rn << 5) | rt


def blr(rn: int) -> int:
    return 0xD63F0000 | (rn << 5)


def ret() -> int:
    return 0xD65F03C0


def nop() -> int:
    return 0xD503201F


# --- ELF assembly -----------------------------------------------------------------------------

EM_AARCH64 = 183
# Android shared objects are linked at base vaddr 0, so virtual addresses equal file
# offsets and a Frida hook offset is just the symbol's vaddr. .text is placed a page in,
# where a real library's code starts, so addresses are realistic.
BASE = 0
TEXT_OFF = 0x1000


def build(key: bytes, sign: bytes, vtable_off: int = 0xE8, symbols: dict[str, int] | None = None,
          decoy_strings: tuple[bytes, ...] = (), swap_arg_order: bool = False,
          wrong_lengths: bool = False, trailing_call_string: bytes | None = None,
          stub_symbols: tuple[str, ...] = ()) -> bytes:
    """Returns a shared object whose applicationDidFinishLaunching makes the key/sign call."""
    # .rodata: decoys first so the real strings are not simply the first ones in the section.
    rodata = bytearray()
    offsets = {}
    extras = (trailing_call_string,) if trailing_call_string else ()
    for blob in (*decoy_strings, key, sign, *extras):
        offsets[bytes(blob)] = len(rodata)
        rodata += blob + b"\0"

    # Lay out .text then .rodata inside one PT_LOAD. Virtual addresses are kept equal to file
    # offsets: tools that map by program header (radare2 among them) would otherwise read the wrong
    # bytes, while anything reading section headers would not notice.
    # Each stub symbol gets its own one-instruction function, so it does not split the
    # main one: radare2 stops analysing at the next function boundary.
    n_insn = 12 + (3 if trailing_call_string else 0) + len(stub_symbols)
    text_off = TEXT_OFF
    rodata_off = (text_off + n_insn * 4 + 0xF) & ~0xF
    text_vaddr, rodata_vaddr = BASE + text_off, BASE + rodata_off
    key_at = rodata_vaddr + offsets[bytes(key)]
    sign_at = rodata_vaddr + offsets[bytes(sign)]

    def emit() -> list[int]:
        pc = text_vaddr
        out: list[int] = []

        def put(word: int) -> None:
            nonlocal pc
            out.append(word)
            pc += 4

        put(ldr_x(8, 0, 0))                 # x8 = *this            (vtable pointer)
        put(nop())                          # filler, as real code has
        first, second = (sign_at, key_at) if swap_arg_order else (key_at, sign_at)
        fl, sl = (len(sign), len(key)) if swap_arg_order else (len(key), len(sign))
        if wrong_lengths:  # two string arguments, but not a key/signature call
            fl, sl = fl + 3, sl + 3
        put(adrp(1, pc, first))
        put(add_imm(1, 1, first & 0xFFF))
        put(movz_w(2, fl))
        put(adrp(3, pc, second))
        put(add_imm(3, 3, second & 0xFFF))
        put(movz_w(4, sl))
        put(ldr_x(5, 8, vtable_off))        # x5 = vtable[slot]     (setXXTEAKeyAndSign)
        put(blr(5))
        if trailing_call_string:
            # A later call that sets up only x1. The scanner must not pair it with the lengths and
            # signature left in the registers by the call above.
            at = rodata_vaddr + offsets[bytes(trailing_call_string)]
            put(adrp(1, pc, at))
            put(add_imm(1, 1, at & 0xFFF))
            put(blr(5))
        put(nop())
        put(ret())
        for _ in stub_symbols:
            put(ret())
        assert len(out) == n_insn, len(out)
        return out

    text = b"".join(struct.pack("<I", w) for w in emit())
    rodata = bytes(rodata)

    syms = ({"_ZN11AppDelegate29applicationDidFinishLaunchingEv": text_vaddr}
            if symbols is None else dict(symbols))
    main_insns = n_insn - len(stub_symbols)
    for i, stub in enumerate(stub_symbols):
        syms[stub] = text_vaddr + (main_insns + i) * 4

    # .strtab / .symtab
    strtab = bytearray(b"\0")
    sym_entries = [b"\0" * 24]  # STN_UNDEF
    for name, value in syms.items():
        name_off = len(strtab)
        strtab += name.encode() + b"\0"
        # st_name, st_info(GLOBAL|FUNC), st_other, st_shndx(.text=1), st_value, st_size
        size = len(text) if value == text_vaddr else 4
        sym_entries.append(struct.pack("<IBBHQQ", name_off, (1 << 4) | 2, 0, 1, value, size))
    symtab = b"".join(sym_entries)

    shstrtab = bytearray(b"\0")
    sh_names = {}
    for name in (".text", ".rodata", ".symtab", ".strtab", ".shstrtab"):
        sh_names[name] = len(shstrtab)
        shstrtab += name.encode() + b"\0"

    ehsize, phentsize, shentsize = 64, 56, 64
    phoff = ehsize
    phnum = 1
    # vaddr == BASE + file offset throughout, so the single PT_LOAD maps one to one.
    file_text = text_off
    file_rodata = rodata_off
    file_symtab = file_rodata + len(rodata)
    file_strtab = file_symtab + len(symtab)
    file_shstr = file_strtab + len(strtab)
    file_sh = (file_shstr + len(shstrtab) + 0xF) & ~0xF

    out = bytearray(file_sh + 6 * shentsize)
    out[0:16] = b"\x7fELF\x02\x01\x01\x00" + b"\0" * 8
    struct.pack_into("<HHIQQQIHHHHHH", out, 16,
                     3,            # e_type = ET_DYN
                     EM_AARCH64, 1,
                     text_vaddr,   # e_entry
                     phoff, file_sh, 0,
                     ehsize, phentsize, phnum, shentsize, 6, 5)

    load_size = file_shstr + len(shstrtab)
    struct.pack_into("<IIQQQQQQ", out, phoff,
                     1, 5,         # PT_LOAD, R+X
                     0, BASE, BASE, load_size, load_size, 0x1000)

    out[file_text:file_text + len(text)] = text
    out[file_rodata:file_rodata + len(rodata)] = rodata
    out[file_symtab:file_symtab + len(symtab)] = symtab
    out[file_strtab:file_strtab + len(strtab)] = strtab
    out[file_shstr:file_shstr + len(shstrtab)] = shstrtab

    def section(i, name, stype, flags, addr, off, size, link=0, info=0, align=1, entsize=0):
        struct.pack_into("<IIQQQQIIQQ", out, file_sh + i * shentsize,
                         sh_names[name], stype, flags, addr, off, size, link, info, align, entsize)

    section(0, ".text", 0, 0, 0, 0, 0)  # index 0 must be SHT_NULL; overwritten below
    struct.pack_into("<IIQQQQIIQQ", out, file_sh, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    section(1, ".text", 1, 0x6, text_vaddr, file_text, len(text), align=4)       # ALLOC|EXEC
    section(2, ".rodata", 1, 0x2, rodata_vaddr, file_rodata, len(rodata), align=1)
    section(3, ".symtab", 2, 0, 0, file_symtab, len(symtab), link=4, info=1, align=8, entsize=24)
    section(4, ".strtab", 3, 0, 0, file_strtab, len(strtab), align=1)
    section(5, ".shstrtab", 3, 0, 0, file_shstr, len(shstrtab), align=1)
    return bytes(out)


if __name__ == "__main__":
    import sys
    blob = build(b"cocos2d_lua_js", b"LJ",
                 decoy_strings=(b"base/", b"applicationDidFinishLaunching", b"res/"))
    path = sys.argv[1] if len(sys.argv) > 1 else "libfake.so"
    with open(path, "wb") as f:
        f.write(blob)
    print(f"wrote {path} ({len(blob)} bytes)")
