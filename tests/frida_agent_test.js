'use strict';
/**
 * Behaviour tests for coconuts/frida_hook.js, run against the Frida stub in fake_frida.js.
 *
 * Usage: node frida_agent_test.js <dir with rendered agent variants>
 * The variants are produced by tests/test_frida_agent.py via build_frida_script().
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { createEnv } = require('./fake_frida');

const RENDERED = process.argv[2];
if (!RENDERED) {
    console.error('usage: node frida_agent_test.js <rendered-dir>');
    process.exit(2);
}

const LUA_BRIDGE = 'Java_org_cocos2dx_lib_Cocos2dxLuaJavaBridge_callLuaFunctionWithString';
const JS_BRIDGE = 'Java_org_cocos2dx_lib_Cocos2dxJavascriptJavaBridge_evalString';
const LUA_KEY_SYM = '_ZN7cocos2d8LuaStack19setXXTEAKeyAndSignEPKciS2_i';
const DO_DLOPEN = '__dl__Z9do_dlopenPKciPK17android_dlextinfoPKv';
// Android 14's linker64 also exports the lambda defined inside do_dlopen, and lists it first.
const DO_DLOPEN_LAMBDA =
    '__dl__ZZ9do_dlopenPKciPK17android_dlextinfoPKvENK3$_5clEv.__uniq.250007671217850615957365636956552013758';
const DUMP_OFF = 0x200, KEY_OFF = 0x300;  // must match test_frida_agent.py

let failures = 0, total = 0;
let group = '';
function section(name) { group = name; console.log('\n' + name); }
function check(name, cond, extra) {
    total++;
    if (cond) { console.log('  ok   ' + name); return true; }
    failures++;
    console.log('  FAIL ' + name + (extra === undefined ? '' : '  -> ' + extra));
    return false;
}

/** Fresh process image with the agent loaded and a linker present unless told otherwise. */
function boot(variant, opts) {
    const o = opts || {};
    const F = createEnv();
    if (!o.noLinker) {
        F.makeModule('linker64', {
            symbols: o.linkerSymbols || (o.strippedLinker ? [] : [DO_DLOPEN]),
        });
    }
    if (!o.noLibdl) F.makeModule('libdl.so', { exports: ['android_dlopen_ext', 'dlopen'] });
    if (o.preload) o.preload(F);
    const src = fs.readFileSync(path.join(RENDERED, variant), 'utf8');
    vm.runInContext(src, vm.createContext(Object.assign({}, F.env)), { filename: variant });
    F.linker = F.modules.find((m) => m.name === 'linker64');
    F.dlopen = (soname) => {
        const target = F.linker && F.linker._symbols.length
            ? F.linker._symbols[0].address
            : F.modules.find((m) => m.name === 'libdl.so').findExportByName('android_dlopen_ext');
        F.fire(target, [F.allocStr('/data/app/com.example/lib/arm64/' + soname)]);
    };
    return F;
}

const luaLib = (F, extra) => F.makeModule('libcocos2dlua.so', {
    exports: [LUA_BRIDGE, LUA_KEY_SYM, 'luaL_loadbufferx', 'luaL_loadbuffer'].concat(extra || []),
    symbols: [LUA_KEY_SYM, 'luaL_loadbufferx', 'luaL_loadbuffer'],
});

// ===========================================================================
section('[1] installation on a Lua engine');
{
    const F = boot('lua.js');
    // do_dlopen plus both public entry points: three loader hooks and nothing engine-side yet.
    // All three are attached on purpose -- see [8].
    check('only loader hooks before the engine lib is mapped', F.attached.size === 3, F.attached.size);
    const lib = luaLib(F);
    F.resetStats();
    F.dlopen('libcocos2dlua.so');

    check('luaL_loadbufferx hooked', F.attached.has(lib.findExportByName('luaL_loadbufferx').addr));
    // Both loaders are hooked when both exist. On LuaJIT they are two separate functions after
    // inlining, and the one Cocos calls is luaL_loadbuffer: hooking only luaL_loadbufferx
    // dumped nothing at all on a real LuaJIT engine. Duplicates are handled by the dedup, which
    // [6] covers.
    check('luaL_loadbuffer also hooked (LuaJIT calls this one)',
        F.attached.has(lib.findExportByName('luaL_loadbuffer').addr));
    check('setXXTEAKeyAndSign hooked', F.attached.has(lib.findExportByName(LUA_KEY_SYM).addr));
    check('export table read at most once', F.stats().enumExportCalls <= 1, F.stats().enumExportCalls);
    check('symbol table read at most once', F.stats().enumSymbolCalls <= 1, F.stats().enumSymbolCalls);

    F.clear();
    F.resetStats();
    F.dlopen('libGLESv2.so');
    check('later dlopen of an unrelated lib does no work', F.stats().enumExportCalls === 0);
}

// ===========================================================================
section('[2] dump hooks are resolved independently');
// Regression: the Lua loader used to be looked up only when evalString was absent, so a Lua lib
// whose evalString offset had been pre-resolved by radare2 silently lost its dump hook.
{
    const F = boot('js_offsets.js');
    const lib = F.makeModule('libcocos2dlua.so', {
        exports: [LUA_BRIDGE, 'luaL_loadbufferx'], symbols: ['luaL_loadbufferx'],
    });
    F.dlopen('libcocos2dlua.so');
    check('evalString hooked at base+DUMP_OFFSET', F.attached.has(lib.base.add(DUMP_OFF).addr));
    check('luaL_loadbufferx hooked as well', F.attached.has(lib.findExportByName('luaL_loadbufferx').addr));
}

// ===========================================================================
section('[3] Lua key capture');
{
    const F = boot('lua.js');
    const lib = luaLib(F);
    F.dlopen('libcocos2dlua.so');
    const hook = lib.findExportByName(LUA_KEY_SYM);
    const key = F.allocStr('mysecretkey'), sign = F.allocStr('XXTEA');

    F.fire(hook, [F.int(0xdead), key, F.int(11), sign, F.int(5)]);
    F.fire(hook, [F.int(0xdead), key, F.int(11), sign, F.int(5)]);
    const keys = F.ofType('key');
    check('key reported exactly once', keys.length === 1, keys.length);
    check('key bytes correct', keys[0] && Buffer.from(keys[0].payload.key, 'hex').toString() === 'mysecretkey');
    check('signature reported', keys[0] && Buffer.from(keys[0].payload.sign, 'hex').toString() === 'XXTEA');
}
{
    // The C-string overload: the length slot holds something that isn't a plausible length.
    const F = boot('lua.js');
    const lib = luaLib(F);
    F.dlopen('libcocos2dlua.so');
    F.fire(lib.findExportByName(LUA_KEY_SYM),
        [F.int(0xdead), F.allocStr('fromcstring'), F.int(0), F.allocStr('SIGN'), F.int(0)]);
    const keys = F.ofType('key');
    check('falls back to a NUL-terminated key',
        keys.length === 1 && Buffer.from(keys[0].payload.key, 'hex').toString() === 'fromcstring',
        keys[0] && keys[0].payload.key);
    check('and to a NUL-terminated signature',
        keys[0] && Buffer.from(keys[0].payload.sign, 'hex').toString() === 'SIGN');
}
{
    const F = boot('lua.js');
    const lib = luaLib(F);
    F.dlopen('libcocos2dlua.so');
    const hook = lib.findExportByName(LUA_KEY_SYM);
    const long = 'x'.repeat(200);
    F.fire(hook, [F.int(0xdead), F.allocStr(long), F.int(200), F.allocStr('S'), F.int(1)]);
    check('an implausibly long key is rejected', F.ofType('key').length === 0);
}

// ===========================================================================
section('[4] JS key capture: xxtea_decrypt and std::string setters');
{
    const F = boot('js_offsets.js');
    const lib = F.makeModule('libcocos2djs.so', { exports: [JS_BRIDGE], symbols: [] });
    F.dlopen('libcocos2djs.so');
    // xxtea_decrypt(data, dataLen, key, keyLen)
    F.fire(lib.base.add(KEY_OFF), [F.int(1), F.int(100), F.allocStr('abc123'), F.int(6)]);
    const keys = F.ofType('key');
    check('key captured from xxtea_decrypt',
        keys.length === 1 && Buffer.from(keys[0].payload.key, 'hex').toString() === 'abc123');
    check('no signature claimed for the JS path', keys[0] && keys[0].payload.sign === '');
}
{
    const F = boot('stdstring.js');
    const lib = F.makeModule('libcocos2djs.so', { exports: [JS_BRIDGE], symbols: [] });
    F.dlopen('libcocos2djs.so');
    F.fire(lib.base.add(KEY_OFF), [F.int(0xdead), F.allocStdString('ssokey', false)]);
    const keys = F.ofType('key');
    check('short std::string key (SSO) read',
        keys.length === 1 && Buffer.from(keys[0].payload.key, 'hex').toString() === 'ssokey',
        keys[0] && keys[0].payload.key);
}
{
    const F = boot('stdstring.js');
    const lib = F.makeModule('libcocos2djs.so', { exports: [JS_BRIDGE], symbols: [] });
    F.dlopen('libcocos2djs.so');
    const long = 'k'.repeat(40);
    F.fire(lib.base.add(KEY_OFF), [F.int(0xdead), F.allocStdString(long, true)]);
    const keys = F.ofType('key');
    check('heap-allocated std::string key read',
        keys.length === 1 && Buffer.from(keys[0].payload.key, 'hex').toString() === long,
        keys[0] && keys[0].payload.key);
}
{
    const F = boot('lua.js');
    const lib = F.makeModule('libcocos2djs.so', {
        exports: [JS_BRIDGE, 'jsb_set_xxtea_key'], symbols: [],
    });
    // COCOS_SYMBOL is the Lua bridge here, so this lib is claimed by the name fallback.
    F.dlopen('libcocos2djs.so');
    F.fire(lib.findExportByName('jsb_set_xxtea_key'), [F.allocStdString('jsbkey', false), F.int(0)]);
    check('jsb_set_xxtea_key captured',
        F.ofType('key').length === 1 &&
        Buffer.from(F.ofType('key')[0].payload.key, 'hex').toString() === 'jsbkey');
}

// ===========================================================================
section('[5] AES key capture (string_view in either slot order)');
for (const [label, mkArgs] of [
    ['libc++ {ptr,len}', (F, k, iv) => [F.int(0xdead), F.int(1), k.p, k.l, iv.p, iv.l, F.int(3)]],
    ['libstdc++ {len,ptr}', (F, k, iv) => [F.int(0xdead), F.int(1), k.l, k.p, iv.l, iv.p, F.int(3)]],
]) {
    const F = boot('lua.js');
    const lib = F.makeModule('libcocos2dlua.so', {
        exports: [LUA_BRIDGE, '_ZN7cocos2d14EncryptManager18setEncryptEnabledEb'], symbols: [],
    });
    F.dlopen('libcocos2dlua.so');
    const k = { p: F.allocStr('aeskey'), l: F.int(6) };
    const iv = { p: F.allocStr('0123456789abcdef'), l: F.int(16) };
    F.fire(lib.findExportByName('_ZN7cocos2d14EncryptManager18setEncryptEnabledEb'), mkArgs(F, k, iv));
    const got = F.ofType('aeskey');
    check(label + ': key and iv recovered',
        got.length === 1 && Buffer.from(got[0].payload.key, 'hex').toString() === 'aeskey' &&
        Buffer.from(got[0].payload.iv, 'hex').toString() === '0123456789abcdef',
        got[0] && JSON.stringify(got[0].payload));
    check(label + ': flags passed through', got[0] && got[0].payload.flags === 3);
}
{
    const F = boot('lua.js');
    const lib = F.makeModule('libcocos2dlua.so', {
        exports: [LUA_BRIDGE, '_ZN7cocos2d14EncryptManager18setEncryptEnabledEb'], symbols: [],
    });
    F.dlopen('libcocos2dlua.so');
    F.fire(lib.findExportByName('_ZN7cocos2d14EncryptManager18setEncryptEnabledEb'),
        [F.int(0xdead), F.int(0), F.allocStr('aeskey'), F.int(6), F.allocStr('iv'), F.int(2), F.int(0)]);
    check('encryption being disabled is ignored', F.ofType('aeskey').length === 0);
}

// ===========================================================================
section('[6] chunk dumping and dedup');
{
    const F = boot('lua.js');
    const lib = luaLib(F);
    F.dlopen('libcocos2dlua.so');
    const hook = lib.findExportByName('luaL_loadbufferx');
    const body = Buffer.from('print("hello")\n'.repeat(4));
    const bodyPtr = F.alloc(body), name = F.allocStr('@src/main.lua');

    F.clear();
    for (let i = 0; i < 5; i++) F.fire(hook, [F.int(1), bodyPtr, F.int(body.length), name, F.int(0)]);
    let files = F.ofType('file');
    check('five identical loads send once', files.length === 1, files.length);
    check('path preserved', files[0] && files[0].payload.path === '@src/main.lua');
    check('tagged as lua', files[0] && files[0].payload.lang === 'lua');
    check('body intact', files[0] && files[0].data.equals(body));

    const body2 = Buffer.from('print("hot updated")\n');
    F.clear();
    F.fire(hook, [F.int(1), F.alloc(body2), F.int(body2.length), name, F.int(0)]);
    check('a changed body at the same path is re-sent', F.ofType('file').length === 1);

    // Same length, different content: the head/tail hash has to catch it.
    const body3 = Buffer.from('print("HOT UPDATED")\n');
    F.clear();
    F.fire(hook, [F.int(1), F.alloc(body3), F.int(body3.length), name, F.int(0)]);
    check('same length but different bytes is re-sent', F.ofType('file').length === 1);

    F.clear();
    F.fire(hook, [F.int(1), bodyPtr, F.int(body.length), F.allocStr('app.MyApp'), F.int(0)]);
    check('a different chunk name is sent', F.ofType('file').length === 1);
}
{
    // A runtime where luaL_loadbuffer really does chain into luaL_loadbufferx: both hooks fire
    // for one chunk, and the dedup has to collapse them into a single send.
    const F = boot('lua.js');
    const lib = luaLib(F);
    F.dlopen('libcocos2dlua.so');
    const body = Buffer.from('return 1\n');
    const bodyPtr = F.alloc(body), name = F.allocStr('assets/src/main.lua');
    F.clear();
    for (const sym of ['luaL_loadbuffer', 'luaL_loadbufferx']) {
        F.fire(lib.findExportByName(sym), [F.int(1), bodyPtr, F.int(body.length), name, F.int(0)]);
    }
    check('a chunk passing through both loaders is sent once', F.ofType('file').length === 1,
        F.ofType('file').length);
}
{
    // An alias: both names at one address must not stack two trampolines on one function.
    const F = boot('lua.js');
    const lib = F.makeModule('libcocos2dlua.so', {
        exports: [LUA_BRIDGE, 'luaL_loadbufferx'], symbols: ['luaL_loadbufferx'],
    });
    lib._exports.push({ name: 'luaL_loadbuffer', address: lib.findExportByName('luaL_loadbufferx') });
    F.dlopen('libcocos2dlua.so');
    const body = Buffer.from('return 2\n');
    F.clear();
    F.fire(lib.findExportByName('luaL_loadbufferx'),
        [F.int(1), F.alloc(body), F.int(body.length), F.allocStr('assets/src/a.lua'), F.int(0)]);
    check('an aliased loader is hooked once', F.ofType('file').length === 1, F.ofType('file').length);
}
{
    // evalString with a non-positive length falls back to a NUL-terminated read.
    const F = boot('js_offsets.js');
    const lib = F.makeModule('libcocos2djs.so', { exports: [JS_BRIDGE], symbols: [] });
    F.dlopen('libcocos2djs.so');
    const hook = lib.base.add(DUMP_OFF);
    const src = F.allocStr('var x = 1;');
    F.clear();
    F.fire(hook, [F.int(1), src, F.int(0), F.int(0), F.allocStr('src/project.jsc')]);
    F.fire(hook, [F.int(1), src, F.int(0), F.int(0), F.allocStr('src/project.jsc')]);
    const files = F.ofType('file');
    check('text payload sent once', files.length === 1, files.length);
    check('text payload carries the source', files[0] && files[0].payload.text === 'var x = 1;');
    check('no binary blob for the text path', files[0] && files[0].data === null);
}

// ===========================================================================
section('[6b] LuaJIT bytecode loaded with the length left unknown');
// lib_package.c loads embedded bytecode as luaL_loadbuffer(L, bcdata, ~(size_t)0, name), because
// a dump carries its own end. The agent has to walk it rather than trust the length; verified
// against real LuaJIT bytecode on a device too.
{
    const F = boot('lua.js');
    const lib = luaLib(F);
    F.dlopen('libcocos2dlua.so');
    const hook = lib.findExportByName('luaL_loadbufferx');
    const SIZE_MAX = 0xffffffffffffffff;

    // stripped: magic, version, flags=STRIP, one 3-byte prototype, end marker
    const stripped = Buffer.from([0x1b, 0x4c, 0x4a, 0x02, 0x02, 0x03, 0xaa, 0xbb, 0xcc, 0x00]);
    // unstripped: the chunk name is a ULEB128 length plus bytes before the prototypes
    const named = Buffer.from([0x1b, 0x4c, 0x4a, 0x02, 0x00, 0x03, 0x61, 0x62, 0x63,
                               0x02, 0xaa, 0xbb, 0x00]);
    for (const [label, dump] of [['stripped', stripped], ['with a chunk name', named]]) {
        F.clear();
        // Trailing bytes stand in for whatever else is on the engine's heap behind the dump.
        const withTail = Buffer.concat([dump, Buffer.alloc(32, 0xff)]);
        F.fire(hook, [F.int(1), F.alloc(withTail), F.int(SIZE_MAX), F.allocStr('a.luac'), F.int(0)]);
        const files = F.ofType('file');
        check('length recovered, ' + label,
            files.length === 1 && files[0].data.equals(dump),
            files[0] && files[0].data.length + ' bytes, wanted ' + dump.length);
    }

    // A ULEB128 length: 0x81 0x01 is 129, so this dump is longer than one byte could express.
    F.clear();
    const big = Buffer.concat([Buffer.from([0x1b, 0x4c, 0x4a, 0x02, 0x02, 0x81, 0x01]),
                               Buffer.alloc(129, 0x55), Buffer.from([0x00])]);
    F.fire(hook, [F.int(1), F.alloc(big), F.int(SIZE_MAX), F.allocStr('b.luac'), F.int(0)]);
    check('multi-byte ULEB128 prototype length', F.ofType('file')[0] &&
        F.ofType('file')[0].data.equals(big), F.ofType('file')[0] &&
        F.ofType('file')[0].data.length + ' bytes, wanted ' + big.length);

    // Not bytecode, and not a length either: nothing to recover, so nothing is sent.
    for (const [label, body] of [
        ['plain source', Buffer.from('print("x")\n')],
        ['PUC Lua bytecode', Buffer.concat([Buffer.from('\x1bLua\x53'), Buffer.alloc(32)])],
        ['unknown LuaJIT flags', Buffer.from([0x1b, 0x4c, 0x4a, 0x02, 0x40, 0x01, 0xaa, 0x00])],
    ]) {
        F.clear();
        F.fire(hook, [F.int(1), F.alloc(body), F.int(SIZE_MAX), F.allocStr('c.luac'), F.int(0)]);
        check('an unknown length is not guessed at: ' + label, F.ofType('file').length === 0,
            JSON.stringify(F.ofType('file').map((m) => m.payload.path)));
    }
}

// ===========================================================================
section('[7] degenerate hook arguments');
{
    const F = boot('lua.js');
    const lib = luaLib(F);
    F.dlopen('libcocos2dlua.so');
    const hook = lib.findExportByName('luaL_loadbufferx');
    const body = F.alloc(Buffer.from('print(1)')), name = F.allocStr('@a.lua');
    F.clear();
    const cases = [
        ['null buffer', [F.int(1), F.int(0), F.int(10), name, F.int(0)]],
        ['null name', [F.int(1), body, F.int(10), F.int(0), F.int(0)]],
        ['zero length', [F.int(1), body, F.int(0), name, F.int(0)]],
        ['absurd length', [F.int(1), body, F.int(0xfffffff0), name, F.int(0)]],
        ['unmapped buffer', [F.int(1), F.int(0xfffff0), F.int(64), name, F.int(0)]],
        ['unmapped name', [F.int(1), body, F.int(16), F.int(0xfffff0), F.int(0)]],
        ['source passed as name', [F.int(1), body, F.int(8), body, F.int(0)]],
    ];
    for (const [label, args] of cases) {
        let threw = null;
        try { F.fire(hook, args); } catch (e) { threw = e; }
        check('survives ' + label, threw === null, threw && threw.message);
    }
    check('nothing sent for any of them', F.ofType('file').length === 0,
        JSON.stringify(F.ofType('file').map((m) => m.payload)));
}

// ===========================================================================
section('[8] loader fallbacks');
{
    const F = boot('lua.js', { strippedLinker: true });
    const adl = F.modules.find((m) => m.name === 'libdl.so').findExportByName('android_dlopen_ext');
    check('android_dlopen_ext hooked when do_dlopen is missing', F.attached.has(adl.addr));
    check('the fallback is logged', F.logs(/relying on android_dlopen_ext/).length === 1);
    const lib = luaLib(F);
    F.dlopen('libcocos2dlua.so');
    check('engine still hooked through it', F.attached.has(lib.findExportByName('luaL_loadbufferx').addr));
}
{
    // No linker and no libdl: only the poll can still find the library.
    const F = boot('lua.js', { noLinker: true, noLibdl: true });
    check('warns that no dlopen hook could be installed', F.logs(/No dlopen hook/).length === 1);
    const lib = luaLib(F);
    check('not hooked yet', !F.attached.has(lib.findExportByName('luaL_loadbufferx').addr));
    F.runTimers(1);
    check('the poll finds the library', F.attached.has(lib.findExportByName('luaL_loadbufferx').addr));
}
{
    const F = boot('lua.js');
    const lib = luaLib(F);
    F.dlopen('libcocos2dlua.so');
    const rounds = F.runTimers(200);
    check('the poll stops once hooked', rounds < 200, rounds);
}
{
    const F = boot('lua.js', { preload: (F2) => luaLib(F2) });
    check('a library already mapped at load is hooked immediately',
        F.attached.has(F.modules.find((m) => m.name === 'libcocos2dlua.so')
            .findExportByName('luaL_loadbufferx').addr));
}

// ===========================================================================
section('[9] library identification');
{
    const F = boot('badsym.js');  // the JNI bridge symbol r2 picked is not in this lib
    const lib = luaLib(F);
    F.dlopen('libcocos2dlua.so');
    check('matched by libcocos*.so name instead', F.attached.has(lib.findExportByName('luaL_loadbufferx').addr));
    check('and says so', F.logs(/matched by name/).length === 1);
}
{
    const F = boot('badsym.js');
    const dud = F.makeModule('libcocosblah.so', { exports: ['unrelated'], symbols: [] });
    F.dlopen('libcocosblah.so');
    check('a name match with no usable symbols does not claim the lib',
        !F.attached.has(dud.findExportByName('unrelated').addr));
    // ...and must not latch `hooked`, or the real engine lib would never be instrumented.
    const real = F.makeModule('libcocos2djs.so', {
        exports: ['_ZN7cocos2d12ScriptEngine10evalStringEPKcl', 'xxtea_decrypt'], symbols: [],
    });
    F.dlopen('libcocos2djs.so');
    check('so a library arriving later is still hooked',
        F.attached.has(real.findExportByName('xxtea_decrypt').addr));
}
{
    const F = boot('lua.js');
    const other = F.makeModule('libfoo.so', { exports: ['main'], symbols: [] });
    F.resetStats();
    let threw = null;
    try { F.dlopen('libfoo.so'); } catch (e) { threw = e; }
    check('a non-Cocos library is ignored without throwing', threw === null, threw && threw.message);
    check('and is not hooked', !F.attached.has(other.findExportByName('main').addr));
    check('its symbol tables are never read',
        F.stats().enumExportCalls === 0 && F.stats().enumSymbolCalls === 0);
}
{
    // enumerateSymbols throwing must not abort installation of the export-based hooks.
    const F = boot('lua.js');
    const lib = F.makeModule('libcocos2dlua.so', {
        exports: [LUA_BRIDGE, LUA_KEY_SYM], symbols: ['luaL_loadbufferx'], symbolsThrow: true,
    });
    let threw = null;
    try { F.dlopen('libcocos2dlua.so'); } catch (e) { threw = e; }
    check('an unreadable symbol table does not abort installation', threw === null, threw && threw.message);
    check('export-based hooks still attached', F.attached.has(lib.findExportByName(LUA_KEY_SYM).addr));
    check('and the lost dump hook is reported', F.logs(/live script dumps disabled/).length === 1);
}

// ===========================================================================
section('[10] real Cocos chunk names and paths (verified on a Pixel 7)');
{
    // The name forms a real engine passes, from cocos2d-x v3 CCLuaStack.cpp:
    //   executeScriptFile   -> FileUtils::fullPathForFilename(), with no '@' prefix
    //   loadChunksFromZIP   -> zip entry minus its extension, '/' and '\' turned into '.'
    //   hot-updated scripts -> an absolute path under the app's writable directory
    // Each one is placed on the heap with other bytes right behind it, because that is what
    // killed this on a device: the name was read with a byte count rather than up to the NUL,
    // so every chunk name came back with ~1000 characters of trailing heap attached and was
    // rejected by LUA_CHUNK_NAME. Nothing was dumped and nothing was logged.
    const F = boot('lua.js');
    const lib = luaLib(F);
    F.dlopen('libcocos2dlua.so');
    const hook = lib.findExportByName('luaL_loadbufferx');
    const body = Buffer.from('local M = {}\nreturn M\n');
    const names = [
        'assets/src/main.lua',
        'assets/src/app/views/MainScene.lua',
        'app.views.MainScene',
        '/data/user/0/com.example.game/files/src/hot.lua',
        '@src/main.lua',   // the '@' form plain Lua uses, which Cocos itself does not
    ];
    for (const n of names) {
        F.clear();
        F.fire(hook, [F.int(1), F.alloc(body), F.int(body.length), F.allocStrAmidGarbage(n), F.int(0)]);
        const files = F.ofType('file');
        check('name read up to the NUL: ' + n,
            files.length === 1 && files[0].payload.path === n,
            files[0] && JSON.stringify(files[0].payload.path.slice(0, 60)));
        check('body intact: ' + n, files[0] && files[0].data.equals(body));
    }
}
{
    // Bytecode is binary: it carries NULs and must be read by length, not as a string.
    const F = boot('lua.js');
    const lib = luaLib(F);
    F.dlopen('libcocos2dlua.so');
    const luac = Buffer.concat([Buffer.from('\x1bLuaS\x00\x19\x93\r\n\x1a\n'), Buffer.alloc(40)]);
    F.clear();
    F.fire(lib.findExportByName('luaL_loadbufferx'),
        [F.int(1), F.alloc(luac), F.int(luac.length), F.allocStrAmidGarbage('assets/src/main.luac'), F.int(0)]);
    const files = F.ofType('file');
    check('bytecode dumped whole', files.length === 1 && files[0].data.equals(luac),
        files[0] && files[0].data.length);
}

// ===========================================================================
section('[11] the loader hook attaches to do_dlopen itself, not a lambda inside it');
{
    // On a Pixel 7 (Android 14) linker64 lists the closure inside do_dlopen before do_dlopen.
    // Taking the first symbol merely containing 'do_dlopen' hooked that closure: the attach
    // succeeded, installLoaderHook() reported success, and the hook was never called.
    const F = boot('lua.js', { linkerSymbols: [DO_DLOPEN_LAMBDA, DO_DLOPEN] });
    const syms = F.modules.find((m) => m.name === 'linker64').enumerateSymbols();
    const addrOf = (n) => syms.find((s) => s.name === n).address.addr;
    check('do_dlopen itself is hooked', F.attached.has(addrOf(DO_DLOPEN)));
    check('the lambda inside it is not', !F.attached.has(addrOf(DO_DLOPEN_LAMBDA)));
}
{
    // Even with do_dlopen hooked, the public entry points are hooked too: attaching to
    // do_dlopen is not proof that it is on the call path.
    const F = boot('lua.js');
    const libdl = F.modules.find((m) => m.name === 'libdl.so');
    check('android_dlopen_ext hooked as well',
        F.attached.has(libdl.findExportByName('android_dlopen_ext').addr));
    check('dlopen hooked as well', F.attached.has(libdl.findExportByName('dlopen').addr));
    // A library reaching the agent through both hooks must still be instrumented once.
    const lib = luaLib(F);
    F.dlopen('libcocos2dlua.so');
    F.fire(libdl.findExportByName('dlopen'), [F.allocStr('/lib/libcocos2dlua.so')]);
    check('a second loader callback does not re-install hooks',
        F.logs(/Hooks installed/).length === 1, F.logs(/Hooks installed/).length);
}

console.log('\n' + total + ' checks, ' + (failures || 'no') + ' failure' + (failures === 1 ? '' : 's'));
process.exit(failures ? 1 : 0);
