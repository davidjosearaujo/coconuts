'use strict';

var COCOS_SYMBOL = __COCOS_SYMBOL__;
var DUMP_OFFSET  = __DUMP_OFFSET__;
var KEY_OFFSET   = __KEY_OFFSET__;
var KEY_IS_STD_STRING = __KEY_IS_STD_STRING__;
var MAX_KEY_LEN  = 64;

var hooked = false;
var keySent = false;
var aesSent = false;

function toHex(buf) {
    var bytes = new Uint8Array(buf);
    var out = '';
    for (var i = 0; i < bytes.length; i++) out += ('0' + bytes[i].toString(16)).slice(-2);
    return out;
}

// A string_view passed by value spans two arg slots: one pointer, one length. The order is
// STL-dependent (libc++ is {ptr,len}, libstdc++ is {len,ptr}), so rather than guess, try both
// orderings and keep whichever gives a plausible length AND a readable span. A wrong guess is
// rejected because the length is out of range or the "pointer" doesn't point at readable memory.
function readSpan(pp, lp) {
    if (!lp.toUInt32) return null;
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

function readStdString(strPtr) {
    if (strPtr.isNull()) return null;
    var firstByte = strPtr.readU8();
    if ((firstByte & 1) === 0) {
        var len = firstByte >> 1;
        if (len === 0 || len > MAX_KEY_LEN) return null;
        return strPtr.add(1).readByteArray(len);
    } else {
        var len = strPtr.add(8).readU64().toNumber();
        if (len === 0 || len > MAX_KEY_LEN) return null;
        var dataPtr = strPtr.add(16).readPointer();
        return dataPtr.isNull() ? null : dataPtr.readByteArray(len);
    }
}

function findExportMatching(lib, substrings) {
    var exps = lib.enumerateExports();
    for (var i = 0; i < exps.length; i++) {
        var name = exps[i].name;
        var matchAll = true;
        for (var j = 0; j < substrings.length; j++) {
            if (name.indexOf(substrings[j]) < 0) {
                matchAll = false;
                break;
            }
        }
        if (matchAll) return exps[i].address;
    }
    return null;
}

function installHooks(lib) {
    hooked = true;
    var base = lib.base;

    // 1. ScriptEngine::evalString(this, const char *script, ssize_t length, Value *ret, const char *fileName)
    var dumpAddr = (DUMP_OFFSET !== null)
        ? base.add(DUMP_OFFSET)
        : (findExportMatching(lib, ['ScriptEngine', 'evalString']) ||
           findExportMatching(lib, ['ScriptingCore', 'evalString']));

    if (dumpAddr !== null) {
        Interceptor.attach(dumpAddr, {
            onEnter: function (args) {
                try {
                    var script = args[1], name = args[4];
                    if (script.isNull() || name.isNull()) return;
                    var path = name.readCString();
                    if (!path) return;
                    var len = args[2].toInt32();
                    if (len > 0) {
                        send({type: 'file', path: path}, script.readByteArray(len));
                    } else {
                        send({type: 'file', path: path, text: script.readUtf8String()});
                    }
                } catch (e) {
                    send({type: 'log', level: 'debug', msg: 'dump hook: ' + e});
                }
            }
        });
    } else {
        send({type: 'log', level: 'warning', msg: 'No evalString hook found; live script dumps disabled (key capture only).'});
    }

    // 2. XXTEA Key Hook: xxtea_decrypt or setXXTeaKey / jsb_set_xxtea_key
    var keyAddr = (KEY_OFFSET !== null)
        ? base.add(KEY_OFFSET)
        : (lib.findExportByName('xxtea_decrypt') || findExportMatching(lib, ['xxtea_decrypt']));

    if (keyAddr !== null) {
        Interceptor.attach(keyAddr, {
            onEnter: function (args) {
                if (keySent) return;
                try {
                    if (KEY_IS_STD_STRING) {
                        var buf = readStdString(args[1]) || readStdString(args[0]);
                        if (buf) {
                            send({type: 'key', key: toHex(buf)});
                            keySent = true;
                        }
                    } else {
                        if (args[2].isNull()) return;
                        var keyLen = args[3].toUInt32();
                        if (keyLen === 0 || keyLen > MAX_KEY_LEN) return;
                        send({type: 'key', key: toHex(args[2].readByteArray(keyLen))});
                        keySent = true;
                    }
                } catch (e) {
                    send({type: 'log', level: 'debug', msg: 'key hook: ' + e});
                }
            }
        });
    }

    var setKeyExp = findExportMatching(lib, ['jsb_set_xxtea_key']) || findExportMatching(lib, ['setXXTeaKey']);
    if (setKeyExp !== null && (keyAddr === null || !setKeyExp.equals(keyAddr))) {
        Interceptor.attach(setKeyExp, {
            onEnter: function (args) {
                if (keySent) return;
                try {
                    var buf = readStdString(args[0]) || readStdString(args[1]);
                    if (buf) {
                        send({type: 'key', key: toHex(buf)});
                        keySent = true;
                    }
                } catch (e) {}
            }
        });
    }

    // 3. AES key capture (EncryptManager::setEncryptEnabled(this, bool, string_view key,
    //    string_view ivec, int flags)). Each string_view occupies two arg slots {ptr,len};
    //    which slot is which varies by STL, so pick the pointer-looking one and read `len` bytes.
    var aesExp = findExportMatching(lib, ['EncryptManager', 'setEncryptEnabled']);
    if (aesExp !== null) {
        Interceptor.attach(aesExp, {
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
                    send({type: 'log', level: 'debug', msg: 'aes hook: ' + e});
                }
            }
        });
    }

    send({type: 'log', level: 'info', msg: 'Hooks installed in ' + lib.name + ' @ ' + base});
}

function tryHook(libname) {
    if (hooked || !libname) return;
    var lib = Process.findModuleByName(libname);
    if (lib !== null && lib.findExportByName(COCOS_SYMBOL) !== null) installHooks(lib);
}

var linker = Process.findModuleByName(Process.pointerSize === 4 ? 'linker' : 'linker64');
if (linker === null) throw new Error('linker module not found');
var doDlopen = null;
linker.enumerateSymbols().forEach(function (sym) {
    if (sym.name.indexOf('do_dlopen') >= 0) doDlopen = sym.address;
});
if (doDlopen === null) throw new Error('do_dlopen not found in ' + linker.name);

Interceptor.attach(doDlopen, {
    onEnter: function (args) {
        var p = args[0].isNull() ? null : args[0].readCString();
        this.libname = p ? p.split('/').pop() : '';
    },
    onLeave: function (retval) {
        tryHook(this.libname);
    }
});

// In case the lib is already loaded
Process.enumerateModules().forEach(function (m) { tryHook(m.name); });
