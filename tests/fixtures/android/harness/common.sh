# Shared by build.sh and build_luajit.sh (source it, don't run it).
#
# Every runtime comes out in the same four symbol shapes, which is the matrix that decides
# whether the agent can find luaL_loadbuffer(x) at all in a real game:
#
#   default-unstripped  - exported, found by findExportByName
#   default-stripped    - .symtab gone, .dynsym survives: still exported
#   hidden-unstripped   - local symbol, only reachable through enumerateSymbols()
#   hidden-stripped     - gone entirely: the agent must degrade, not crash

NDK=${NDK:-/home/davidjosearaujo/Android/Sdk/ndk/30.0.16248370}
TC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin
CC=$TC/aarch64-linux-android21-clang
CXX=$TC/aarch64-linux-android21-clang++
STRIP=$TC/llvm-strip

HARNESS=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BASE=${OUT_DIR:-$HARNESS/..}
VARIANTS=(default-unstripped default-stripped hidden-unstripped hidden-stripped)

# prepare_out <runtime> [lua-bytecode-compiler]
# Sets OUT, clears it, and writes the runtime's chunk table. The compiler, when given, produces
# the bytecode case with the very Lua version the library embeds.
prepare_out() {
    OUT=$BASE/$1
    rm -rf "$OUT"
    mkdir -p "$OUT/obj"
    for v in "${VARIANTS[@]}"; do mkdir -p "$OUT/$v"; done
    python3 "$HARNESS/gen_chunks.py" "${2:-}" "$OUT/chunks.h" >/dev/null
}

# compile_harness <variant> <visibility-flags> <runtime include dir> [extra engine flags]
# Compiles the three harness sources (xxtea, LuaStack, engine) into $OUT/obj.
compile_harness() {
    local name=$1 vis=$2 inc=$3 engine_flags=${4:-}
    "$CC"  -c -O2 -fPIC $vis -I"$inc" -I"$HARNESS" -I"$OUT" \
           -o "$OUT/obj/xxtea_$name.o" "$HARNESS/xxtea_min.c"
    "$CXX" -c -O2 -fPIC $vis -I"$inc" -I"$HARNESS" -I"$OUT" \
           -o "$OUT/obj/luastack_$name.o" "$HARNESS/luastack.cpp"
    "$CXX" -c -O2 -fPIC $vis $engine_flags -I"$inc" -I"$HARNESS" -I"$OUT" \
           -o "$OUT/obj/engine_$name.o" "$HARNESS/engine_main.cpp"
}

# link_variant <variant> <runtime objects/archives and flags...>
link_variant() {
    local name=$1; shift
    "$CXX" -shared -fPIC -o "$OUT/$name/libcocos2dlua.so" \
           "$OUT/obj/xxtea_$name.o" "$OUT/obj/luastack_$name.o" "$OUT/obj/engine_$name.o" \
           "$@" -lm -ldl -llog -static-libstdc++
}

# The stripped variants are the unstripped ones with --strip-all applied.
make_stripped_variants() {
    cp "$OUT/default-unstripped/libcocos2dlua.so" "$OUT/default-stripped/libcocos2dlua.so"
    cp "$OUT/hidden-unstripped/libcocos2dlua.so"  "$OUT/hidden-stripped/libcocos2dlua.so"
    "$STRIP" --strip-all "$OUT/default-stripped/libcocos2dlua.so"
    "$STRIP" --strip-all "$OUT/hidden-stripped/libcocos2dlua.so"
}

# One driver serves every runtime: it only dlopen()s whatever library it is given.
build_driver() {
    "$CC" -O2 -o "$BASE/driver" "$HARNESS/driver.c" -ldl
}

report_shapes() {
    echo
    echo "== $1: where each variant carries the loader symbols =="
    local v so
    for v in "${VARIANTS[@]}"; do
        so=$OUT/$v/libcocos2dlua.so
        printf "  %-20s size=%-9s dynsym:%s symtab:%s\n" "$v" "$(stat -c%s "$so")" \
          "$("$TC/llvm-readelf" --dyn-syms "$so" 2>/dev/null | grep -oE 'luaL_loadbufferx?$' | sort -u | tr '\n' ',')" \
          "$("$TC/llvm-readelf" --symbols "$so" 2>/dev/null | grep -oE 'luaL_loadbufferx?$' | sort -u | tr '\n' ',')"
    done
}
