#!/bin/bash
# Builds the on-device Lua loader harness for arm64 Android against a PUC Lua source tree.
# See common.sh for the four symbol shapes each runtime is built in.
#
# Usage: build.sh <runtime-name> <lua-src-dir> [extra-cflags]
set -euo pipefail
source "$(dirname "$0")/common.sh"

RUNTIME=${1:?runtime name, e.g. lua53}
LUA_SRC=${2:?path to the lua src/ dir}
EXTRA=${3:-}

# The chunk table uses this runtime's own luac (a host build), so the bytecode case is bytecode
# this very Lua version will actually load.
LUAC=""
[ -x "$LUA_SRC/luac" ] && LUAC=$LUA_SRC/luac
prepare_out "$RUNTIME" "$LUAC"

# Lua core + libs, minus the standalone interpreter and compiler drivers.
LUA_C=$(ls "$LUA_SRC"/*.c | grep -vE '/(lua|luac)\.c$')

# The Lua core is compiled once per visibility mode: a real engine builds Lua with the same
# flags as the rest of the lib, so hiding only the harness files would leave Lua still exported
# and the "hidden" variant would prove nothing.
compile_core() {
    local mode=$1 vis=$2 f
    echo "== $RUNTIME: compiling Lua core for arm64 ($mode) =="
    mkdir -p "$OUT/obj/core-$mode"
    for f in $LUA_C; do
        "$CC" -c -O2 -fPIC -DLUA_USE_POSIX $vis -I"$LUA_SRC" $EXTRA \
              -o "$OUT/obj/core-$mode/$(basename "$f" .c).o" "$f"
    done
}

build_variant() {
    local name=$1 mode=$2 vis=$3
    echo "== $RUNTIME/$name =="
    compile_harness "$name" "$vis" "$LUA_SRC"
    link_variant "$name" "$OUT"/obj/core-"$mode"/*.o
}

VIS_HIDDEN="-fvisibility=hidden -fvisibility-inlines-hidden"
compile_core default ""
compile_core hidden  "$VIS_HIDDEN"

build_variant default-unstripped default ""
build_variant hidden-unstripped  hidden  "$VIS_HIDDEN"
make_stripped_variants
build_driver
report_shapes "$RUNTIME"
