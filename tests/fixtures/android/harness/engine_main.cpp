/*
 * The "engine" side of the harness: what libcocos2dlua.so exposes and does at startup.
 * Mirrors the order a real Cocos Lua game does it in: set the XXTEA key and signature, then
 * load each script through LuaStack::luaLoadBuffer.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
}
#include "luastack.h"
#include "chunks.h"

#ifdef HARNESS_LUAJIT
#include <stdlib.h>
/** Collects a lua_dump() into one buffer, so the harness can load its own bytecode back. */
struct bc_buf { char *data; size_t len; };

static int bc_writer(lua_State *L, const void *p, size_t sz, void *ud)
{
    (void)L;
    bc_buf *b = (bc_buf *)ud;
    char *grown = (char *)realloc(b->data, b->len + sz);
    if (!grown) return 1;
    memcpy(grown + b->len, p, sz);
    b->data = grown;
    b->len += sz;
    return 0;
}
#endif

// Matches r2.py's Java_\w*(?:Javascript|Lua)JavaBridge\w* bridge-export check, which is how
// coconuts decides a library is a Cocos engine lib at all.
extern "C" __attribute__((visibility("default")))
int Java_org_cocos2dx_lib_Cocos2dxLuaJavaBridge_retainLuaFunction(void *env, void *thiz, int handler)
{
    (void)env; (void)thiz;
    return handler;
}

/**
 * Reports which vtable slot setXXTEAKeyAndSign landed in, so the index a vtable-walking hook
 * would need is confirmed by a real compiler rather than assumed. `setter` is the address the
 * driver resolved for the mangled symbol; without it (a hidden-visibility build) there is
 * nothing to compare the vtable entries against.
 */
static void report_vtable_slot(cocos2d::LuaStack *stack, void *setter)
{
    if (!setter) {
        printf("[engine] the setter is not exported here; cannot locate its vtable slot\n");
        return;
    }
    void **vt = *(void ***)stack;
    for (int i = 0; i < 64; i++) {
        if (vt[i] == setter) {
            printf("[engine] setXXTEAKeyAndSign is vtable slot %d (+%#x with %zu-bit pointers)\n",
                   i, (unsigned)(i * sizeof(void *)), sizeof(void *) * 8);
            return;
        }
    }
    printf("[engine] setXXTEAKeyAndSign is not in the first 64 vtable slots\n");
}

extern "C" __attribute__((visibility("default")))
int cocos_run_scripts(void *setter)
{
    lua_State *L = luaL_newstate();
    if (!L) {
        fprintf(stderr, "[engine] luaL_newstate failed\n");
        return 1;
    }
    luaL_openlibs(L);

    cocos2d::LuaStack stack;
    stack.setState(L);
    report_vtable_slot(&stack, setter);

    // With HARNESS_ZERO_LEN_KEY set, the key and signature lengths are passed as 0, the way a
    // fork relying on NUL-terminated strings would. That is what the agent's C-string fallback
    // is for, and it is otherwise only covered by the Node stub.
    if (getenv("HARNESS_ZERO_LEN_KEY")) {
        printf("[engine] setting the key with zero lengths (NUL-terminated strings)\n");
        stack.setXXTEAKeyAndSign(HARNESS_XXTEA_KEY, 0, HARNESS_XXTEA_SIGN, 0);
        stack.setXXTEAKeyAndSign(HARNESS_XXTEA_KEY, HARNESS_XXTEA_KEY_LEN,
                                 HARNESS_XXTEA_SIGN, HARNESS_XXTEA_SIGN_LEN);
    } else {
        stack.setXXTEAKeyAndSign(HARNESS_XXTEA_KEY, HARNESS_XXTEA_KEY_LEN,
                                 HARNESS_XXTEA_SIGN, HARNESS_XXTEA_SIGN_LEN);
    }

    int loaded = 0, failed = 0;
    for (int i = 0; i < HARNESS_CHUNK_COUNT; i++) {
        const chunk_case_t *c = &harness_chunks[i];
        int r = stack.luaLoadBuffer(L, (const char *)c->data, (int)c->size, c->name);
        if (r == 0) {
            loaded++;
            printf("[engine] loaded  %-52s (%s)\n", c->name, c->label);
            lua_pop(L, 1);   // drop the compiled chunk
        } else {
            failed++;
            printf("[engine] FAILED  %-52s (%s)\n", c->name, c->label);
        }
    }

    // luaL_loadstring: the chunk name IS the source. The agent must NOT dump these as files.
    const char *codes[] = {
        "print('hot path')",          // punctuation: rejected by the name filter
        "collectgarbage",             // bare identifier: looks like a module name
    };
    for (unsigned i = 0; i < sizeof codes / sizeof codes[0]; i++) {
        int r = stack.executeString(codes[i]);
        printf("[engine] loadstring %-50s -> %d\n", codes[i], r);
    }

#ifdef HARNESS_LUAJIT
    // LuaJIT's own lib_package.c loads embedded bytecode as
    //     luaL_loadbuffer(L, bcdata, ~(size_t)0, name)
    // i.e. with the length deliberately unknown, because LuaJIT bytecode is self-delimiting.
    // The bytecode is produced here, on the device, so it matches this build exactly.
    {
        const char *src = "return 7";
        if (luaL_loadbuffer(L, src, strlen(src), "=bcgen") == 0) {
            bc_buf bc = {NULL, 0};
            if (lua_dump(L, bc_writer, &bc) == 0 && bc.data) {
                lua_pop(L, 1);  // drop the chunk we dumped
                printf("[engine] embedded bytecode is %zu bytes; loading it with sz=~(size_t)0\n",
                       bc.len);
                int r = luaL_loadbuffer(L, bc.data, ~(size_t)0, "assets/src/embedded.luac");
                printf("[engine] lib_package-style load -> %d\n", r);
                if (r == 0) lua_pop(L, 1);
            }
            free(bc.data);
        }
    }
#endif

    printf("[engine] done: %d loaded, %d failed\n", loaded, failed);
    lua_close(L);
    return failed;
}
