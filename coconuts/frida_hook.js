'use strict';

var COCOS_SYMBOL = __COCOS_SYMBOL__;
var DUMP_OFFSET  = __DUMP_OFFSET__;
var KEY_OFFSET   = __KEY_OFFSET__;
var KEY_IS_STD_STRING = __KEY_IS_STD_STRING__;

var MAX_KEY_LEN   = 64;
var MAX_CHUNK_LEN = 64 * 1024 * 1024;  // sanity bound before readByteArray on an attacker-sized length
var MAX_NAME_LEN  = 1024;              // cap name reads so a missing NUL can't run off the mapping
var MAX_SEEN      = 20000;             // bound on the dedup table

var hooked = false;
var keySent = false;
var aesSent = false;
var triedModules = {};   // module name -> true, so a miss isn't retried on every dlopen
var seenChunks = {};     // dedup tag -> true
var seenCount = 0;
var keyHookAddrs = [];   // every address a key hook is already attached to

// Nothing below may throw out of a hook: an exception inside onEnter propagates into the game's
// own call, and an exception during installation would leave the agent half-hooked.
function logMsg(level, msg) {
    try {
        send({type: 'log', level: level, msg: String(msg)});
    } catch (e) {}
}

function safeAttach(label, addr, callbacks) {
    if (addr === null || addr === undefined || addr.isNull()) return false;
    try {
        Interceptor.attach(addr, callbacks);
        logMsg('debug', 'hooked ' + label + ' @ ' + addr);
        return true;
    } catch (e) {
        logMsg('debug', 'could not hook ' + label + ' @ ' + addr + ': ' + e);
        return false;
    }
}

function globalExport(name) {
    try {
        if (typeof Module.findGlobalExportByName === 'function') {
            return Module.findGlobalExportByName(name);
        }
    } catch (e) {}
    try {
        return Module.findExportByName(null, name);  // older Frida
    } catch (e) {}
    return null;
}

function toHex(buf) {
    var bytes = new Uint8Array(buf);
    var out = '';
    for (var i = 0; i < bytes.length; i++) out += ('0' + bytes[i].toString(16)).slice(-2);
    return out;
}

// ---------------------------------------------------------------------------
// Symbol lookup
//
// enumerateExports()/enumerateSymbols() are the expensive part of installation (tens of thousands
// of entries on an engine .so) and it all runs inside the linker's dlopen, on the game's main
// thread during startup. So each table is read at most once and every lookup scans the cache.
// ---------------------------------------------------------------------------

function SymbolIndex(lib) {
    this.lib = lib;
    this._exports = null;
    this._symbols = null;
}

SymbolIndex.prototype.exports = function () {
    if (this._exports === null) {
        try {
            this._exports = this.lib.enumerateExports();
        } catch (e) {
            logMsg('debug', 'enumerateExports failed: ' + e);
            this._exports = [];
        }
    }
    return this._exports;
};

// The full symbol table is only touched when an export lookup misses: Lua is linked into the
// engine lib and its symbols are often local rather than exported.
SymbolIndex.prototype.symbols = function () {
    if (this._symbols === null) {
        try {
            this._symbols = this.lib.enumerateSymbols();
        } catch (e) {
            logMsg('debug', 'enumerateSymbols failed: ' + e);
            this._symbols = [];
        }
    }
    return this._symbols;
};

function scanExact(list, name) {
    for (var i = 0; i < list.length; i++) {
        if (list[i].name === name && list[i].address && !list[i].address.isNull()) {
            return list[i].address;
        }
    }
    return null;
}

/** First of `names` (in preference order) found as an export, then in the symbol table. */
SymbolIndex.prototype.firstExact = function (names) {
    var i, addr;
    for (i = 0; i < names.length; i++) {
        try {
            addr = this.lib.findExportByName(names[i]);  // resolver lookup, no enumeration
            if (addr !== null && !addr.isNull()) return addr;
        } catch (e) {}
    }
    for (i = 0; i < names.length; i++) {
        addr = scanExact(this.exports(), names[i]);
        if (addr !== null) return addr;
    }
    for (i = 0; i < names.length; i++) {
        addr = scanExact(this.symbols(), names[i]);
        if (addr !== null) return addr;
    }
    return null;
};

/**
 * Every distinct address among `names`. Two names resolving to one address (an alias, or a
 * build where the wrapper really is a tail call) yield a single entry, so nothing gets hooked
 * twice at the same place.
 */
SymbolIndex.prototype.allExact = function (names) {
    var out = [];
    for (var i = 0; i < names.length; i++) {
        var addr = this.firstExact([names[i]]);
        if (addr === null || addr.isNull()) continue;
        var dup = false;
        for (var j = 0; j < out.length; j++) {
            if (out[j].equals(addr)) { dup = true; break; }
        }
        if (!dup) out.push(addr);
    }
    return out;
};

function matchesAll(name, parts) {
    for (var j = 0; j < parts.length; j++) {
        if (name.indexOf(parts[j]) < 0) return false;
    }
    return true;
}

/**
 * First entry matching any of `needles` (each an array of substrings that must all be present),
 * in needle order. C++ methods are matched this way because the mangled name varies by build.
 */
SymbolIndex.prototype.firstMatching = function (needles, includeSymbols) {
    var lists = [this.exports()];
    if (includeSymbols) lists.push(this.symbols());
    for (var l = 0; l < lists.length; l++) {
        var list = lists[l];
        for (var n = 0; n < needles.length; n++) {
            for (var i = 0; i < list.length; i++) {
                if (list[i].address && !list[i].address.isNull() && matchesAll(list[i].name, needles[n])) {
                    return list[i].address;
                }
            }
        }
    }
    return null;
};

// ---------------------------------------------------------------------------
// Argument readers
// ---------------------------------------------------------------------------

// A string_view passed by value spans two arg slots: one pointer, one length. The order is
// STL-dependent (libc++ is {ptr,len}, libstdc++ is {len,ptr}), so rather than guess, try both
// orderings and keep whichever gives a plausible length AND a readable span. A wrong guess is
// rejected because the length is out of range or the "pointer" doesn't point at readable memory.
function readSpan(pp, lp) {
    if (!lp || !lp.toUInt32) return null;
    var len = lp.toUInt32();
    if (len === 0 || len > MAX_KEY_LEN || pp.isNull()) return null;
    try {
        return pp.readByteArray(len);  // throws if pp isn't readable (i.e. pp was really the length)
    } catch (e) {
        return null;
    }
}

function readStringView(a, b) {
    return readSpan(a, b) || readSpan(b, a);  // {ptr,len} first, then {len,ptr}
}

// libc++ std::string (the only ABI Android ships, and r2.py rejects non-arm64 libs): SSO flag in
// the low bit of byte 0, otherwise {cap, size, data*} with size at +8 and data at +16.
function readStdString(strPtr) {
    if (!strPtr || strPtr.isNull()) return null;
    try {
        var firstByte = strPtr.readU8();
        if ((firstByte & 1) === 0) {
            var sso = firstByte >> 1;
            if (sso === 0 || sso > MAX_KEY_LEN) return null;
            return strPtr.add(1).readByteArray(sso);
        }
        var len = strPtr.add(8).readU64().toNumber();
        if (len === 0 || len > MAX_KEY_LEN) return null;
        var dataPtr = strPtr.add(16).readPointer();
        return dataPtr.isNull() ? null : dataPtr.readByteArray(len);
    } catch (e) {
        return null;
    }
}

/**
 * Reads a NUL-terminated name (a chunk name, a script path, a library path).
 *
 * The size argument of readCString() must not be used for this. On Frida 17 a bounded read
 * returns `size` bytes whatever the string's own length is, and the NUL does not survive
 * decoding, so it cannot even be trimmed afterwards: on a device, readCString(1024) over
 * "assets/src/main.lua" came back as 1023 characters of the heap behind it with no NUL in
 * sight, and every chunk name was then rejected by LUA_CHUNK_NAME. Reading without a size
 * stops at the NUL, and an unreadable page throws instead of returning junk, so the length
 * is checked after the fact rather than up front.
 */
function readName(p, maxLen) {
    if (!p || p.isNull()) return null;
    var s;
    try {
        s = p.readCString();
    } catch (e) {
        return null;  // not readable (a bogus pointer, or the mapping ends mid-string)
    }
    if (!s || s.length === 0 || s.length > maxLen) return null;
    return s;
}

// Reads a (const char *, int len) pair, or a NUL-terminated string when the length slot isn't a
// plausible length (an overload that takes bare C strings).
function readCharsAndLen(p, lenArg) {
    if (!p || p.isNull()) return null;
    try {
        var len = lenArg ? lenArg.toUInt32() : 0;
        if (len > 0 && len <= MAX_KEY_LEN) return p.readByteArray(len);
        var s = readName(p, MAX_KEY_LEN);
        if (s === null) return null;
        return p.readByteArray(s.length);
    } catch (e) {
        return null;
    }
}

// ---------------------------------------------------------------------------
// Script dumping
// ---------------------------------------------------------------------------

// Lua chunk names are file paths ('@src/main.lua') or module names ('app.MyApp'); luaL_loadstring
// passes the source itself as the name, which this rejects.
var LUA_CHUNK_NAME = /^[@=]?[\w.\/\\-]{1,255}$/;

function fnv1a(bytes, h) {
    h = h >>> 0;
    for (var i = 0; i < bytes.length; i++) {
        h = (h ^ bytes[i]) >>> 0;
        h = (h + (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24)) >>> 0;
    }
    return h >>> 0;
}

// A chunk is identified by its length plus a hash of its first and last 64 bytes. Hashing the
// whole body would cost more than it saves; this is only here to tell a re-load of the same
// script apart from a hot-updated one that reuses its path.
function bytesTag(buf) {
    var all = new Uint8Array(buf);
    var h = fnv1a(all.subarray(0, Math.min(64, all.length)), 2166136261);
    if (all.length > 64) h = fnv1a(all.subarray(all.length - 64), h);
    return all.length + ':' + h.toString(16);
}

function textTag(text) {
    var h = 2166136261, i;
    var head = Math.min(64, text.length);
    for (i = 0; i < head; i++) h = fnv1a([text.charCodeAt(i) & 0xff], h);
    for (i = Math.max(head, text.length - 64); i < text.length; i++) h = fnv1a([text.charCodeAt(i) & 0xff], h);
    return text.length + ':' + h.toString(16);
}

/**
 * True when this exact chunk was already sent. Scripts are loaded repeatedly (module reloads,
 * coroutines, a second Lua state), and every duplicate costs a blocking send of the whole body
 * over USB from the game's own thread.
 */
function alreadySent(path, tag) {
    var k = path + '\u0000' + tag;
    if (seenChunks[k] === true) return true;
    if (seenCount < MAX_SEEN) {
        seenChunks[k] = true;
        seenCount++;
    }
    return false;
}

function emitBytes(path, lang, ptr, len) {
    if (!(len > 0) || len > MAX_CHUNK_LEN || ptr.isNull()) return;
    var buf = ptr.readByteArray(len);
    if (buf === null) return;
    if (alreadySent(path, bytesTag(buf))) return;
    var meta = {type: 'file', path: path};
    if (lang) meta.lang = lang;
    send(meta, buf);
}

function emitText(path, lang, text) {
    if (!text) return;
    if (alreadySent(path, textTag(text))) return;
    var meta = {type: 'file', path: path, text: text};
    if (lang) meta.lang = lang;
    send(meta);
}

function hookLuaLoadBuffer(addr) {
    // luaL_loadbuffer(L, const char *buff, size_t sz, const char *name) (luaL_loadbufferx adds mode)
    return safeAttach('luaL_loadbuffer(x)', addr, {
        onEnter: function (args) {
            try {
                var buff = args[1], name = args[3];
                if (buff.isNull() || name.isNull()) return;
                var path = readName(name, MAX_NAME_LEN);
                if (!path || !LUA_CHUNK_NAME.test(path)) return;
                emitBytes(path, 'lua', buff, args[2].toUInt32());
            } catch (e) {
                logMsg('debug', 'lua dump hook: ' + e);
            }
        }
    });
}

function hookEvalString(addr) {
    // ScriptEngine::evalString(this, const char *script, ssize_t length, Value *ret, const char *fileName)
    return safeAttach('evalString', addr, {
        onEnter: function (args) {
            try {
                var script = args[1], name = args[4];
                if (script.isNull() || name.isNull()) return;
                var path = readName(name, MAX_NAME_LEN);
                if (!path) return;
                var len = args[2].toInt32();
                if (len > 0) {
                    emitBytes(path, null, script, len);
                } else {
                    emitText(path, null, script.readUtf8String());  // length omitted: NUL-terminated
                }
            } catch (e) {
                logMsg('debug', 'dump hook: ' + e);
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Key capture
// ---------------------------------------------------------------------------

/**
 * Attaches a key hook whose `reader(args)` returns {key, sign} or null. Targets are deduped
 * against each other, not just against the primary one: two needles can resolve to the same
 * address (an alias, or a name that matches both patterns), and attaching twice would report
 * the key twice and stack two trampolines on one function.
 */
function attachKeyHook(label, addr, reader) {
    if (addr === null || addr.isNull()) return false;
    for (var i = 0; i < keyHookAddrs.length; i++) {
        if (keyHookAddrs[i].equals(addr)) return false;
    }
    var ok = safeAttach(label, addr, {
        onEnter: function (args) {
            if (keySent) return;
            try {
                var r = reader(args);
                if (!r || !r.key) return;
                send({type: 'key', key: toHex(r.key), sign: r.sign ? toHex(r.sign) : ''});
                keySent = true;
            } catch (e) {
                logMsg('debug', label + ' hook: ' + e);
            }
        }
    });
    if (ok) keyHookAddrs.push(addr);
    return ok;
}

// xxtea_decrypt(data, dataLen, key, keyLen), or setXXTeaKey(std::string) when the address came
// from the .data.rel.ro probe (r2.py decides which, and says so via KEY_IS_STD_STRING).
function readXxteaKey(args) {
    if (KEY_IS_STD_STRING) {
        var buf = readStdString(args[1]) || readStdString(args[0]);
        return buf ? {key: buf} : null;
    }
    if (args[2].isNull()) return null;
    var keyLen = args[3].toUInt32();
    if (keyLen === 0 || keyLen > MAX_KEY_LEN) return null;
    return {key: args[2].readByteArray(keyLen)};
}

function readStdStringKey(args) {
    var buf = readStdString(args[0]) || readStdString(args[1]);
    return buf ? {key: buf} : null;
}

// LuaStack::setXXTEAKeyAndSign(this, const char *key, int keyLen, const char *sign, int signLen)
function readLuaKeyAndSign(args) {
    var key = readCharsAndLen(args[1], args[2]);
    if (!key) return null;
    return {key: key, sign: readCharsAndLen(args[3], args[4])};
}

// ---------------------------------------------------------------------------
// Installation
// ---------------------------------------------------------------------------

function installHooks(lib) {
    var base = lib.base;
    var idx = new SymbolIndex(lib);
    var attached = 0;

    // 1. Script dumping. The two loaders are resolved independently and both are attached when
    //    both exist: an engine lib can carry an evalString symbol and still run Lua, and
    //    DUMP_OFFSET being pre-resolved by r2 must not suppress the Lua hook.
    var dumpAddr = (DUMP_OFFSET !== null)
        ? base.add(DUMP_OFFSET)
        : idx.firstMatching([['ScriptEngine', 'evalString'], ['ScriptingCore', 'evalString']]);

    // Every Lua loader symbol present is hooked, not just the first one found.
    //
    // Which symbols exist depends on the runtime: Lua 5.2+ makes luaL_loadbuffer a macro, so
    // only luaL_loadbufferx is in the binary; Lua 5.1 has only luaL_loadbuffer; LuaJIT declares
    // both. On LuaJIT the two are NOT one function calling the other in practice. lj_load.c's
    // luaL_loadbuffer does call luaL_loadbufferx, but they sit in one translation unit and at
    // -O2 the callee is inlined into the wrapper: on an arm64 device both came out as separate
    // complete 148-byte functions with no branch between them. Since LuaStack::luaLoadBuffer
    // calls luaL_loadbuffer, hooking only luaL_loadbufferx dumped nothing at all on a LuaJIT
    // engine while still reporting a healthy hook.
    //
    // Where the two really do chain (an unoptimised build, or an alias at one address), both
    // hooks fire for the same chunk; alreadySent() drops the duplicate, since it keys on the
    // chunk name plus a hash of the body.
    var luaLoadAddrs = idx.allExact(['luaL_loadbufferx', 'luaL_loadbuffer']);

    var luaHooks = 0;
    for (var li = 0; li < luaLoadAddrs.length; li++) {
        if (hookLuaLoadBuffer(luaLoadAddrs[li])) luaHooks++;
    }
    attached += luaHooks;
    if (dumpAddr !== null && hookEvalString(dumpAddr)) attached++;
    if (luaHooks === 0 && dumpAddr === null) {
        logMsg('warning', 'No evalString / luaL_loadbuffer hook found; live script dumps disabled (key capture only).');
    }

    // 2. XXTEA key capture: xxtea_decrypt, setXXTeaKey / jsb_set_xxtea_key (JS), and
    //    LuaStack::setXXTEAKeyAndSign (Lua). All three are tried on every engine: which one
    //    exists is what tells the engines apart, so nothing here branches on JS vs Lua.
    var keyAddr = (KEY_OFFSET !== null)
        ? base.add(KEY_OFFSET)
        : idx.firstExact(['xxtea_decrypt']) || idx.firstMatching([['xxtea_decrypt']]);
    if (attachKeyHook('xxtea_decrypt', keyAddr, readXxteaKey)) attached++;

    var setKeyExp = idx.firstMatching([['jsb_set_xxtea_key'], ['setXXTeaKey']]);
    if (attachKeyHook('setXXTeaKey', setKeyExp, readStdStringKey)) attached++;

    var luaKeyExp = idx.firstMatching([['LuaStack', 'setXXTEAKeyAndSign']], true);
    if (attachKeyHook('LuaStack::setXXTEAKeyAndSign', luaKeyExp, readLuaKeyAndSign)) attached++;

    // 3. AES key capture (EncryptManager::setEncryptEnabled(this, bool, string_view key,
    //    string_view ivec, int flags)). Each string_view occupies two arg slots {ptr,len};
    //    which slot is which varies by STL, so pick the pointer-looking one and read `len` bytes.
    var aesExp = idx.firstMatching([['EncryptManager', 'setEncryptEnabled']]);
    var aesOk = safeAttach('EncryptManager::setEncryptEnabled', aesExp, {
        onEnter: function (args) {
            if (aesSent) return;
            try {
                if (args[1].toInt32() === 0) return;  // bVal == false: encryption being disabled
                var key = readStringView(args[2], args[3]);
                var iv  = readStringView(args[4], args[5]);
                if (!key) return;
                send({type: 'aeskey', key: toHex(key), iv: iv ? toHex(iv) : '',
                      flags: args[6].toInt32()});
                aesSent = true;
            } catch (e) {
                logMsg('debug', 'aes hook: ' + e);
            }
        }
    });
    if (aesOk) attached++;

    return attached;
}

// Fallback identification for a lib whose JNI bridge symbol isn't the one r2 picked (a different
// Cocos version, or a renamed bridge). Only honoured when hooks actually attach.
var COCOS_LIB_NAME = /^libcocos.*\.so$/i;

function tryHook(libname) {
    if (hooked || !libname || triedModules[libname] === true) return;

    var lib = null;
    try {
        lib = Process.findModuleByName(libname);
    } catch (e) {
        lib = null;
    }
    if (lib === null) return;  // not mapped yet; leave it retryable

    triedModules[libname] = true;

    var confirmed = false;
    try {
        confirmed = !!COCOS_SYMBOL && lib.findExportByName(COCOS_SYMBOL) !== null;
    } catch (e) {}
    if (!confirmed && !COCOS_LIB_NAME.test(libname)) return;

    var attached = 0;
    try {
        attached = installHooks(lib);
    } catch (e) {
        logMsg('warning', 'Hook installation failed in ' + libname + ': ' + e);
        return;
    }

    if (confirmed || attached > 0) {
        hooked = true;
        logMsg('info', 'Hooks installed in ' + lib.name + ' @ ' + lib.base +
                       ' (' + attached + ' hook(s)' + (confirmed ? '' : ', matched by name') + ')');
    }
}

function scanLoadedModules() {
    if (hooked) return;
    var mods;
    try {
        mods = Process.enumerateModules();
    } catch (e) {
        return;
    }
    for (var i = 0; i < mods.length && !hooked; i++) tryHook(mods[i].name);
}

var dlopenCallbacks = {
    onEnter: function (args) {
        this.libname = '';
        try {
            var p = readName(args[0], MAX_NAME_LEN);
            if (p) this.libname = p.split('/').pop();
        } catch (e) {}
    },
    onLeave: function () {
        try {
            tryHook(this.libname);
        } catch (e) {
            logMsg('debug', 'dlopen hook: ' + e);
        }
    }
};

/**
 * The address of the linker's do_dlopen, in one pass over its symbol table (it is large, and
 * this runs on the game's main thread at startup). Ranked rather than first-match: the mangled
 * function wins outright, a plain symbol containing the name beats a nested entity (the lambda
 * inside do_dlopen: `_ZZ...`, `$_`, `.__uniq.`), and a nested entity is only a last resort.
 */
function findDoDlopen(syms) {
    var plain = null, nested = null;
    for (var i = 0; i < syms.length; i++) {
        var n = syms[i].name;
        if (n.indexOf('do_dlopen') < 0 || !syms[i].address || syms[i].address.isNull()) continue;
        if (/(^|_)_Z\d+do_dlopen/.test(n)) return syms[i].address;
        if (n.indexOf('$_') < 0 && n.indexOf('.__uniq.') < 0) {
            if (plain === null) plain = syms[i].address;
        } else if (nested === null) {
            nested = syms[i].address;
        }
    }
    return plain !== null ? plain : nested;
}

/**
 * Hooks the loader so the engine lib is instrumented the moment it is mapped. do_dlopen is the
 * linker's internal entry point and returns before the library's .init_array runs, which is what
 * makes it possible to catch a key set from a static initialiser. The public entry points only
 * return after constructors have already run, so they are the weaker of the two -- but they are
 * attached as well, because do_dlopen cannot be relied on to be on the call path.
 */
function installLoaderHook() {
    var linker = null;
    try {
        linker = Process.findModuleByName(Process.pointerSize === 4 ? 'linker' : 'linker64');
    } catch (e) {}

    var any = false;

    if (linker !== null) {
        var doDlopen = null;
        try {
            var syms = linker.enumerateSymbols();
            // A substring match on 'do_dlopen' is not enough. Android 14's linker64 carries two
            // such symbols and the lambda inside do_dlopen comes first:
            //   __dl__ZZ9do_dlopenPKciPK17android_dlextinfoPKvENK3$_5clEv.__uniq.2500...
            //   __dl__Z9do_dlopenPKciPK17android_dlextinfoPKv            <- the function
            // Hooking the lambda attaches cleanly and then never fires, which on a Pixel 7
            // left the agent with no working loader hook at all. So the mangled function name
            // is preferred, and nested-entity symbols (_ZZ..., $_, .__uniq.) are only used as
            // a last resort.
            doDlopen = findDoDlopen(syms);
        } catch (e) {
            logMsg('debug', 'linker symbol scan failed: ' + e);
        }
        if (doDlopen !== null && safeAttach('do_dlopen', doDlopen, dlopenCallbacks)) any = true;
    }

    // The public entry points are attached even when do_dlopen was hooked. Attaching to
    // do_dlopen succeeding does not prove it is on the call path (see above), and a second
    // hook costs nothing: tryHook() dedupes by library name and stops once hooks are in.
    var names = ['android_dlopen_ext', 'dlopen'];
    var pub = false;
    for (var n = 0; n < names.length; n++) {
        if (safeAttach(names[n], globalExport(names[n]), dlopenCallbacks)) pub = true;
    }
    if (pub && !any) {
        logMsg('debug', 'do_dlopen unavailable; relying on android_dlopen_ext/dlopen ' +
                        '(a key set from a static initialiser may be missed).');
    }
    return any || pub;
}

// The lib may already be mapped (attaching to a running process rather than spawning).
scanLoadedModules();

if (!installLoaderHook() && !hooked) {
    logMsg('warning', 'No dlopen hook could be installed; falling back to polling for the engine library.');
}

// Safety net for a library mapped through a path neither hook covers. Stops as soon as the
// engine lib is found, and gives up well after the key timeout rather than polling forever.
var pollsLeft = 120;  // 120 * 250ms = 30s
function poll() {
    if (hooked || pollsLeft-- <= 0) return;
    scanLoadedModules();
    if (!hooked) setTimeout(poll, 250);
}
setTimeout(poll, 250);
