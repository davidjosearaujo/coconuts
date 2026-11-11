#!/bin/bash
# Builds the harness against a cross-compiled LuaJIT (which exports BOTH luaL_loadbuffer and
# luaL_loadbufferx, where loadbuffer is a real wrapper calling loadbufferx -- lj_load.c:162).
#
# LuaJIT comes in as a static archive, so the "hidden" variants use -Wl,--exclude-libs,ALL,
# which localises every symbol coming from a static library. That is what an NDK build does
# when it doesn't want its dependencies' symbols in the dynamic table.
#
# Usage: build_luajit.sh <path to the cross-compiled LuaJIT checkout>
set -euo pipefail
source "$(dirname "$0")/common.sh"

LJ=${1:?path to the LuaJIT checkout}

# No host luac: the engine produces its own LuaJIT bytecode on the device, so it matches the
# build exactly (see engine_main.cpp).
prepare_out luajit ""

build_variant() {
    local name=$1 extra_ld=$2
    echo "== luajit/$name =="
    compile_harness "$name" "" "$LJ/src" -DHARNESS_LUAJIT
    link_variant "$name" "$LJ/src/libluajit.a" $extra_ld
}

build_variant default-unstripped ""
build_variant hidden-unstripped  "-Wl,--exclude-libs,ALL"
make_stripped_variants
build_driver
report_shapes luajit
