#ifndef HARNESS_LUASTACK_H
#define HARNESS_LUASTACK_H

struct lua_State;

namespace cocos2d {

class LuaStack {
public:
    LuaStack();
    ~LuaStack();

    void setXXTEAKeyAndSign(const char *key, int keyLen, const char *sign, int signLen);
    void cleanupXXTEAKeyAndSign();
    int  luaLoadBuffer(lua_State *L, const char *chunk, int chunkSize, const char *chunkName);
    int  executeString(const char *codes);

    void setState(lua_State *L) { _state = L; }

private:
    lua_State *_state;
    bool  _xxteaEnabled;
    char *_xxteaKey;
    int   _xxteaKeyLen;
    char *_xxteaSign;
    int   _xxteaSignLen;
};

} // namespace cocos2d
#endif
