/*
 * A faithful replica of the parts of cocos2d::LuaStack that coconuts' Frida agent hooks,
 * transcribed from cocos2d-x v3 / 3.17.2 cocos/scripting/lua-bindings/manual/CCLuaStack.cpp:
 *
 *   - setXXTEAKeyAndSign(const char *key, int keyLen, const char *sign, int signLen)  (key hook)
 *   - luaLoadBuffer(lua_State *, const char *chunk, int chunkSize, const char *chunkName)
 *     which xxtea-decrypts when the chunk carries the signature and then calls luaL_loadbuffer
 *     with the PLAINTEXT  (the dump hook's whole premise)
 *
 * Built into libcocos2dlua.so so the agent's real symbol resolution runs against real
 * mangled names in a real arm64 ELF.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
}
#include "xxtea_min.h"
#include "luastack.h"

namespace cocos2d {

LuaStack::LuaStack()
    : _state(nullptr), _xxteaEnabled(false), _xxteaKey(nullptr), _xxteaKeyLen(0),
      _xxteaSign(nullptr), _xxteaSignLen(0)
{
}

LuaStack::~LuaStack()
{
    if (_xxteaKey) free(_xxteaKey);
    if (_xxteaSign) free(_xxteaSign);
}

// CCLuaStack.cpp: setXXTEAKeyAndSign(const char *key, int keyLen, const char *sign, int signLen)
void LuaStack::setXXTEAKeyAndSign(const char *key, int keyLen, const char *sign, int signLen)
{
    cleanupXXTEAKeyAndSign();

    if (key && keyLen && sign && signLen) {
        _xxteaKey = (char *)malloc(keyLen);
        memcpy(_xxteaKey, key, keyLen);
        _xxteaKeyLen = keyLen;

        _xxteaSign = (char *)malloc(signLen + 1);
        memcpy(_xxteaSign, sign, signLen);
        _xxteaSign[signLen] = '\0';
        _xxteaSignLen = signLen;

        _xxteaEnabled = true;
    } else {
        _xxteaEnabled = false;
    }
}

void LuaStack::cleanupXXTEAKeyAndSign()
{
    if (_xxteaKey) { free(_xxteaKey); _xxteaKey = nullptr; _xxteaKeyLen = 0; }
    if (_xxteaSign) { free(_xxteaSign); _xxteaSign = nullptr; _xxteaSignLen = 0; }
    _xxteaEnabled = false;
}

// CCLuaStack.cpp: anonymous-namespace skipBOM
static void skipBOM(const char *&chunk, int &chunkSize)
{
    if (chunkSize >= 3 &&
        (unsigned char)chunk[0] == 0xEF &&
        (unsigned char)chunk[1] == 0xBB &&
        (unsigned char)chunk[2] == 0xBF) {
        chunk += 3;
        chunkSize -= 3;
    }
}

// CCLuaStack.cpp: LuaStack::luaLoadBuffer, unchanged in structure.
int LuaStack::luaLoadBuffer(lua_State *L, const char *chunk, int chunkSize, const char *chunkName)
{
    int r = 0;

    if (_xxteaEnabled && strncmp(chunk, _xxteaSign, _xxteaSignLen) == 0) {
        xxtea_long len = 0;
        unsigned char *result = xxtea_decrypt((unsigned char *)chunk + _xxteaSignLen,
                                              (xxtea_long)chunkSize - _xxteaSignLen,
                                              (unsigned char *)_xxteaKey,
                                              (xxtea_long)_xxteaKeyLen,
                                              &len);
        if (!result) {
            fprintf(stderr, "[engine] xxtea_decrypt failed for %s\n", chunkName);
            return 1;
        }
        unsigned char *content = result;
        xxtea_long contentSize = len;
        skipBOM((const char *&)content, (int &)contentSize);
        r = luaL_loadbuffer(L, (char *)content, contentSize, chunkName);
        free(result);
    } else {
        skipBOM(chunk, chunkSize);
        r = luaL_loadbuffer(L, chunk, chunkSize, chunkName);
    }

    if (r) {
        fprintf(stderr, "[engine] load \"%s\" failed: %s\n", chunkName, lua_tostring(L, -1));
        lua_pop(L, 1);
    }
    return r;
}

// CCLuaStack.cpp: LuaStack::executeString -> luaL_loadstring, whose chunk name IS the source.
int LuaStack::executeString(const char *codes)
{
    int r = luaL_loadstring(_state, codes);
    if (r) lua_pop(_state, 1);
    return r;
}

} // namespace cocos2d
