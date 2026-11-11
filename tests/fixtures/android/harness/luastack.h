#ifndef HARNESS_LUASTACK_H
#define HARNESS_LUASTACK_H

#include <functional>

struct lua_State;

namespace cocos2d {

// Stand-ins for the Cocos types the declarations below mention. Only the number and order of
// virtual functions decides the vtable layout, so the parameter types need to be present, not
// real. Anything that would change the layout -- the base class, which functions are virtual,
// their order, and the overloads -- is transcribed exactly.
class LuaValue;
class LuaValueDict;
class LuaValueArray;
class __Array;

/** cocos2d::Ref, whose only virtual member is its destructor (cocos/base/CCRef.h). */
class Ref {
public:
    Ref() : _referenceCount(1) {}
    virtual ~Ref();
    void retain() { _referenceCount++; }
    void release() { _referenceCount--; }          // non-virtual in Cocos too
    unsigned int getReferenceCount() const { return _referenceCount; }

private:
    unsigned int _referenceCount;
};

/**
 * cocos2d::LuaStack, with its virtual functions in the order cocos2d-x v3 and 4.x declare them
 * (cocos/scripting/lua-bindings/manual/CCLuaStack.h). That order is what puts
 * setXXTEAKeyAndSign at a particular vtable slot, so the harness can only confirm which slot
 * that is if the whole list is faithful -- the engine reports it at startup.
 *
 * Only the handful of members coconuts actually hooks have real bodies; the rest are stubs.
 */
class LuaStack : public Ref {
public:
    LuaStack();
    virtual ~LuaStack();

    virtual void addSearchPath(const char *path);
    virtual void addLuaLoader(int (*func)(lua_State *));
    virtual int reload(const char *moduleFileName);
    virtual void removeScriptObjectByObject(Ref *object);
    virtual void removeScriptHandler(int nHandler);
    virtual int reallocateScriptHandler(int nHandler);
    virtual int executeString(const char *codes);
    virtual int executeScriptFile(const char *filename);
    virtual int executeGlobalFunction(const char *functionName);
    virtual void clean();
    virtual void pushInt(int intValue);
    virtual void pushFloat(float floatValue);
    virtual void pushLong(long longValue);
    virtual void pushBoolean(bool boolValue);
    virtual void pushString(const char *stringValue);
    virtual void pushString(const char *stringValue, int length);
    virtual void pushNil();
    virtual void pushObject(Ref *objectValue, const char *typeName);
    virtual void pushLuaValue(const LuaValue &value);
    virtual void pushLuaValueDict(const LuaValueDict &dict);
    virtual void pushLuaValueArray(const LuaValueArray &array);
    virtual bool pushFunctionByHandler(int nHandler);
    virtual int executeFunction(int numArgs);
    virtual int executeFunctionByHandler(int nHandler, int numArgs);
    virtual int executeFunctionReturnArray(int handler, int numArgs, int numResults,
                                           __Array &resultArray);
    virtual int executeFunction(int handler, int numArgs, int numResults,
                               const std::function<void(lua_State *, int)> &func);
    virtual bool handleAssert(const char *msg);
    virtual void setXXTEAKeyAndSign(const char *key, int keyLen, const char *sign, int signLen);
    virtual void cleanupXXTEAKeyAndSign();

    // Non-virtual in Cocos as well, so it must stay out of the vtable.
    int luaLoadBuffer(lua_State *L, const char *chunk, int chunkSize, const char *chunkName);

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
