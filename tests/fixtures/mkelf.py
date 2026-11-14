"""Builds minimal aarch64 ET_DYN ELFs in the two shapes the static searches look for: a
Cocos-shaped setXXTEAKeyAndSign call site (`build`), and a decrypt-failure function whose calls
include the one to xxtea_decrypt (`build_decrypt_fail`).

There is no aarch64 linker on this host, so the fixtures are assembled directly. That is an
advantage for testing anyway: the vtable offset, argument order, register allocation, call order
and each callee's xref count can all be set exactly, where a compiler would decide them for us.
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


def bl(pc: int, target: int) -> int:
    return 0x94000000 | (((target - pc) >> 2) & 0x3FFFFFF)


def br(rn: int) -> int:
    return 0xD61F0000 | (rn << 5)


# The standard aarch64 frame prologue and epilogue. radare2's prelude scan (`aap`) looks for
# these, and without them it never works out where functions begin -- real compiled code has them,
# so the fixtures do too.
STP_FP_LR = 0xA9BF7BFD   # stp x29, x30, [sp, #-16]!
LDP_FP_LR = 0xA8C17BFD   # ldp x29, x30, [sp], #16


def ret() -> int:
    return 0xD65F03C0


def nop() -> int:
    return 0xD503201F


def _pack_rodata(blobs) -> tuple[bytes, dict[bytes, int]]:
    """NUL-terminated strings laid out back to back, with the offset of each."""
    data = bytearray()
    offsets: dict[bytes, int] = {}
    for blob in blobs:
        offsets[bytes(blob)] = len(data)
        data += bytes(blob) + b"\0"
    return bytes(data), offsets


def _layout(n_insn: int) -> tuple[int, int]:
    """The .text and .rodata virtual addresses for a .text of `n_insn` instructions."""
    return BASE + TEXT_OFF, BASE + ((TEXT_OFF + n_insn * 4 + 0xF) & ~0xF)


def _assemble(text: bytes, rodata: bytes, syms: dict[str, int],
              text_vaddr: int, rodata_vaddr: int) -> bytes:
    """Wraps .text and .rodata in an ET_DYN aarch64 ELF with a symbol table.

    Virtual addresses are kept equal to file offsets, so the single PT_LOAD maps one to one:
    tools that map by program header (radare2 among them) would otherwise read the wrong bytes,
    while anything reading section headers would not notice.
    """
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
    file_text = text_vaddr - BASE
    file_rodata = rodata_vaddr - BASE
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
    extras = (trailing_call_string,) if trailing_call_string else ()
    rodata, offsets = _pack_rodata((*decoy_strings, key, sign, *extras))

    # Lay out .text then .rodata inside one PT_LOAD. Virtual addresses are kept equal to file
    # offsets: tools that map by program header (radare2 among them) would otherwise read the wrong
    # bytes, while anything reading section headers would not notice.
    # Each stub symbol gets its own one-instruction function, so it does not split the
    # main one: radare2 stops analysing at the next function boundary.
    n_insn = 12 + (3 if trailing_call_string else 0) + len(stub_symbols)
    text_vaddr, rodata_vaddr = _layout(n_insn)
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

    syms = ({"_ZN11AppDelegate29applicationDidFinishLaunchingEv": text_vaddr}
            if symbols is None else dict(symbols))
    main_insns = n_insn - len(stub_symbols)
    for i, stub in enumerate(stub_symbols):
        syms[stub] = text_vaddr + (main_insns + i) * 4

    return _assemble(text, rodata, syms, text_vaddr, rodata_vaddr)


# --- the "can\'t decrypt code" shape -----------------------------------------------------------
#
# find_key_function() works in two steps: find the function that references the decrypt-failure
# string, then pick the call to xxtea_decrypt out of the `bl`s inside it (the KEY_CALL_INDEX-th,
# with a fallback to whichever callee has exactly two xrefs). Assembling the shape by hand is what
# makes the call order and the xref counts exact; a compiler would decide both for us.

JNI_BRIDGE = "Java_org_cocos2dx_lib_Cocos2dxJavascriptJavaBridge_evalString"


def build_decrypt_fail(needle: bytes = b"Can\'t decrypt code for %s",
                       n_calls: int = 20,
                       key_call_index: int = 12,
                       extra_callers: dict[int, int] | None = None,
                       key_via_plt: bool = False,
                       with_key_symbol: bool = True,
                       with_jdiv: bool = True,
                       decoy_strings: tuple[bytes, ...] = ()) -> tuple[bytes, dict]:
    """A library whose decrypt-failure function calls `n_calls` stubs, one of them the key call.

    `extra_callers` maps a call index to how many additional functions also call that callee, so a
    callee's xref count can be set exactly (the real xxtea_decrypt has two). With `key_via_plt` the
    key call goes to a stub that jumps through x16, like a PLT entry, and the real xxtea_decrypt
    symbol sits elsewhere -- unless `with_key_symbol` is false, when there is nothing to resolve.
    `with_jdiv` adds the integer-division helper every real engine library links in, at the end of
    .text. r2_open_and_analyse bounds its analysis to the span before that symbol, so its presence
    decides which of the two analysis paths runs.

    Returns the ELF and the addresses in it.
    """
    extra_callers = dict(extra_callers or {})
    flat_extras = [idx for idx, count in extra_callers.items() for _ in range(count)]
    # A key_call_index outside the call list means no call is the key call, which is how the
    # "nothing callable in the decrypt-failure function" case is built.
    has_key_call = 0 <= key_call_index < n_calls

    rodata, offsets = _pack_rodata((*decoy_strings, needle))

    MAIN_LEN = n_calls + 5        # prologue, adrp, add, the calls, epilogue, ret
    CALLEE_LEN = 3                # prologue, epilogue, ret
    CALLER_LEN = 4                # prologue, bl, epilogue, ret
    PLT_LEN = 3                   # adrp x16, ldr x16, br x16 -- a PLT entry has no frame

    n_insn = (MAIN_LEN + n_calls * CALLEE_LEN + len(flat_extras) * CALLER_LEN
              + (PLT_LEN + CALLEE_LEN if key_via_plt else 0) + (CALLEE_LEN if with_jdiv else 0))
    text_vaddr, rodata_vaddr = _layout(n_insn)
    needle_at = rodata_vaddr + offsets[bytes(needle)]

    # Addresses first, so the calls can be emitted with their targets resolved.
    at = text_vaddr + MAIN_LEN * 4
    callee_at = []
    for _ in range(n_calls):
        callee_at.append(at)
        at += CALLEE_LEN * 4
    caller_at = []
    for _ in flat_extras:
        caller_at.append(at)
        at += CALLER_LEN * 4
    plt_at = at if key_via_plt else 0
    if key_via_plt:
        real_key_at = plt_at + PLT_LEN * 4
    else:
        real_key_at = callee_at[key_call_index] if has_key_call else 0
    key_target = plt_at if key_via_plt else real_key_at

    words: list[int] = []
    pc = text_vaddr

    def put(word):
        nonlocal pc
        words.append(word)
        pc += 4

    # The decrypt-failure function: it references the string, then makes its calls.
    put(STP_FP_LR)
    put(adrp(0, pc, needle_at))
    put(add_imm(0, 0, needle_at & 0xFFF))
    for i in range(n_calls):
        put(bl(pc, key_target if i == key_call_index and key_target else callee_at[i]))
    put(LDP_FP_LR)
    put(ret())

    for _ in range(n_calls):                     # the callees
        put(STP_FP_LR)
        put(LDP_FP_LR)
        put(ret())
    for idx in flat_extras:                      # extra callers, to set xref counts
        put(STP_FP_LR)
        put(bl(pc, key_target if idx == key_call_index else callee_at[idx]))
        put(LDP_FP_LR)
        put(ret())
    if key_via_plt:
        put(adrp(16, pc, real_key_at))           # the hop through x16 is what marks a PLT stub
        put(ldr_x(16, 16, 0))
        put(br(16))
        put(STP_FP_LR)                           # the real xxtea_decrypt behind it
        put(LDP_FP_LR)
        put(ret())

    jdiv_at = pc if with_jdiv else 0
    if with_jdiv:                                # last, so bounded analysis still covers the rest
        put(STP_FP_LR)
        put(LDP_FP_LR)
        put(ret())

    assert len(words) == n_insn, (len(words), n_insn)
    text = b"".join(struct.pack("<I", w) for w in words)

    syms = {"_ZN12ScriptingCore9runScriptEPKc": text_vaddr, JNI_BRIDGE: text_vaddr}
    if with_jdiv:
        syms["__divdi3_jdiv"] = jdiv_at          # r2.py matches on the 'jdiv' substring
    for i, addr in enumerate(callee_at):
        if i != key_call_index:
            syms[f"stub_{i}"] = addr
    if with_key_symbol and real_key_at:
        syms["xxtea_decrypt"] = real_key_at
    elif not key_via_plt and real_key_at:
        syms[f"stub_{key_call_index}"] = real_key_at

    layout = {"fail_fn": text_vaddr, "callees": callee_at, "key_target": key_target,
              "key_real": real_key_at, "needle_at": needle_at, "callers": caller_at,
              "jdiv": jdiv_at}
    return _assemble(text, rodata, syms, text_vaddr, rodata_vaddr), layout


# --- the LuaStack::luaLoadBuffer shape ---------------------------------------------------------
#
# find_lua_load_function() finds the function referencing one of the "[LUA ERROR] load" strings,
# then picks luaL_loadbuffer out of its `bl`s by call count: the loader is called once and the
# logger once per error case. Measured in a shipped arm64 game, luaLoadBuffer is 184 bytes and
# makes 5 calls -- 1 to luaL_loadbuffer, 4 to cocos2d::log. Assembled by hand so the counts are
# exact rather than whatever a compiler decides.

LUA_BRIDGE = "Java_org_cocos2dx_lib_Cocos2dxLuaJavaBridge_callLuaFunctionWithString"
LUA_LOAD_NEEDLE = b'[LUA ERROR] load "%s", error: syntax error during pre-compilation.'


def build_lua_load(needle: bytes = LUA_LOAD_NEEDLE,
                   n_log: int = 4,
                   n_loader: int = 1,
                   extra_once: int = 0,
                   loader_via_plt: bool = False,
                   with_loader_symbol: bool = False,
                   with_jdiv: bool = True,
                   decoy_strings: tuple[bytes, ...] = ()) -> tuple[bytes, dict]:
    """A library whose Lua load function logs `needle` and calls a logger `n_log` times.

    The loader is called `n_loader` times, so a build where the asymmetry does not hold can be
    tested too. `extra_once` adds further callees called exactly once, which is what makes the
    loader ambiguous. With `loader_via_plt` the loader call goes through an x16 hop like a PLT
    entry, and the real luaL_loadbufferx sits behind it -- found only if `with_loader_symbol`.

    Returns the ELF and the addresses in it.
    """
    rodata, offsets = _pack_rodata((*decoy_strings, needle))

    MAIN_LEN = 5 + n_log + n_loader + extra_once   # stp, adrp, add, the calls, ldp, ret
    CALLEE_LEN = 3
    PLT_LEN = 3
    n_callees = 2 + extra_once                     # the logger, the loader, the extras
    n_insn = (MAIN_LEN + n_callees * CALLEE_LEN
              + (PLT_LEN + CALLEE_LEN if loader_via_plt else 0)
              + (CALLEE_LEN if with_jdiv else 0))
    text_vaddr, rodata_vaddr = _layout(n_insn)
    needle_at = rodata_vaddr + offsets[bytes(needle)]

    at = text_vaddr + MAIN_LEN * 4
    log_at, at = at, at + CALLEE_LEN * 4
    loader_body_at, at = at, at + CALLEE_LEN * 4
    extra_at = []
    for _ in range(extra_once):
        extra_at.append(at)
        at += CALLEE_LEN * 4
    plt_at = at if loader_via_plt else 0
    real_loader_at = (plt_at + PLT_LEN * 4) if loader_via_plt else loader_body_at
    loader_target = plt_at if loader_via_plt else loader_body_at

    words: list[int] = []
    pc = text_vaddr

    def put(word):
        nonlocal pc
        words.append(word)
        pc += 4

    put(STP_FP_LR)
    put(adrp(0, pc, needle_at))
    put(add_imm(0, 0, needle_at & 0xFFF))
    for _ in range(n_loader):
        put(bl(pc, loader_target))
    for a in extra_at:
        put(bl(pc, a))
    for _ in range(n_log):                       # one log call per way the load can fail
        put(bl(pc, log_at))
    put(LDP_FP_LR)
    put(ret())

    for _ in range(n_callees):                   # the logger, the loader, the extras
        put(STP_FP_LR)
        put(LDP_FP_LR)
        put(ret())
    if loader_via_plt:
        put(adrp(16, pc, real_loader_at))        # the hop through x16 is what marks a PLT stub
        put(ldr_x(16, 16, 0))
        put(br(16))
        put(STP_FP_LR)                           # the real luaL_loadbufferx behind it
        put(LDP_FP_LR)
        put(ret())

    jdiv_at = pc if with_jdiv else 0
    if with_jdiv:
        put(STP_FP_LR)
        put(LDP_FP_LR)
        put(ret())

    assert len(words) == n_insn, (len(words), n_insn)
    text = b"".join(struct.pack("<I", w) for w in words)

    # No luaL_loadbuffer symbol unless asked for: a lib that still exports it needs none of this.
    syms = {LUA_BRIDGE: text_vaddr, "_ZN7cocos2d8LuaStack13luaLoadBufferEP9lua_State": text_vaddr}
    if with_jdiv:
        syms["__divdi3_jdiv"] = jdiv_at
    syms["_ZN7cocos2d3logEPKcz"] = log_at
    if with_loader_symbol:
        syms["luaL_loadbufferx"] = real_loader_at

    layout = {"load_fn": text_vaddr, "loader": loader_target, "loader_real": real_loader_at,
              "logger": log_at, "extras": extra_at, "needle_at": needle_at, "jdiv": jdiv_at}
    return _assemble(text, rodata, syms, text_vaddr, rodata_vaddr), layout


if __name__ == "__main__":
    import sys
    blob = build(b"cocos2d_lua_js", b"LJ",
                 decoy_strings=(b"base/", b"applicationDidFinishLaunching", b"res/"))
    path = sys.argv[1] if len(sys.argv) > 1 else "libfake.so"
    with open(path, "wb") as f:
        f.write(blob)
    print(f"wrote {path} ({len(blob)} bytes)")
