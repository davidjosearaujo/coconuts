'use strict';
/**
 * Minimal Frida runtime stub: a flat memory space with NativePointer semantics, plus the
 * Interceptor / Process / Module surface coconuts/frida_hook.js uses.
 *
 * createEnv() returns an isolated process image, so each scenario starts from a clean one.
 */

function createEnv() {
    const MEM = Buffer.alloc(1 << 20);
    let brk = 0x1000;

    class P {
        constructor(addr) { this.addr = Number(addr); }
        isNull() { return this.addr === 0; }
        add(n) { return new P(this.addr + (n instanceof P ? n.addr : Number(n))); }
        equals(o) { return o instanceof P && o.addr === this.addr; }
        toString() { return '0x' + this.addr.toString(16); }
        toUInt32() { return this.addr >>> 0; }
        toInt32() { return this.addr | 0; }
        readU8() { this._chk(1); return MEM.readUInt8(this.addr); }
        readU64() { this._chk(8); return { toNumber: () => Number(MEM.readBigUInt64LE(this.addr)) }; }
        readPointer() { this._chk(8); return new P(Number(MEM.readBigUInt64LE(this.addr))); }
        readByteArray(len) {
            this._chk(len);
            return MEM.buffer.slice(MEM.byteOffset + this.addr, MEM.byteOffset + this.addr + len);
        }
        readCString(max) {
            this._chk(1);
            const cap = max === undefined ? 4096 : max;
            let end = this.addr;
            while (end < MEM.length && end - this.addr < cap && MEM[end] !== 0) end++;
            return MEM.toString('utf8', this.addr, end);
        }
        readUtf8String(n) { return this.readCString(n); }
        // Reads outside the mapping throw, exactly as they do on a device.
        _chk(len) {
            if (!(len >= 0) || this.addr <= 0 || this.addr + len > MEM.length) {
                throw new Error('access violation at ' + this.toString());
            }
        }
    }

    function alloc(buf) {
        const at = brk;
        buf.copy(MEM, at);
        brk = (brk + buf.length + 16 + 7) & ~7;
        return new P(at);
    }
    const allocStr = (s) => alloc(Buffer.concat([Buffer.from(s, 'utf8'), Buffer.from([0])]));

    /** libc++ std::string: SSO packs the length in byte 0; the long form is {cap, size, data*}. */
    function allocStdString(s, longForm) {
        const bytes = Buffer.from(s, 'utf8');
        if (!longForm) {
            return alloc(Buffer.concat([Buffer.from([bytes.length << 1]), bytes, Buffer.from([0])]));
        }
        const data = alloc(Buffer.concat([bytes, Buffer.from([0])]));
        const hdr = Buffer.alloc(24);
        hdr.writeBigUInt64LE(BigInt((bytes.length + 1) | 1), 0);  // capacity, low bit set
        hdr.writeBigUInt64LE(BigInt(bytes.length), 8);
        hdr.writeBigUInt64LE(BigInt(data.addr), 16);
        return alloc(hdr);
    }

    const modules = [];
    const attached = new Map();
    const messages = [];
    const timers = [];
    let enumExportCalls = 0, enumSymbolCalls = 0;

    function makeModule(name, spec) {
        brk = (brk + 0x10000) & ~0xffff;
        const base = new P(brk);
        brk += 0x8000;
        const mk = (names) => (names || []).map((n, i) => ({ name: n, address: base.add(0x100 + i * 0x40) }));
        const mod = {
            name, base,
            _exports: mk(spec.exports),
            _symbols: mk(spec.symbols),
            enumerateExports() { enumExportCalls++; return this._exports; },
            enumerateSymbols() {
                enumSymbolCalls++;
                if (spec.symbolsThrow) throw new Error('symbol table unavailable');
                return this._symbols;
            },
            findExportByName(n) { const e = this._exports.find((x) => x.name === n); return e ? e.address : null; },
        };
        modules.push(mod);
        return mod;
    }

    const env = {
        ptr(v) { return new P(typeof v === 'string' ? parseInt(v, 16) : v); },
        send(payload, data) { messages.push({ payload, data: data ? Buffer.from(data) : null }); },
        Interceptor: {
            attach(addr, cb) {
                if (!(addr instanceof P) || addr.isNull()) throw new Error('bad address');
                if (!attached.has(addr.addr)) attached.set(addr.addr, []);
                attached.get(addr.addr).push(cb);
            },
        },
        Process: {
            pointerSize: 8,
            findModuleByName(n) { return modules.find((m) => m.name === n) || null; },
            enumerateModules() { return modules.slice(); },
        },
        Module: {
            findGlobalExportByName(n) {
                for (const m of modules) { const a = m.findExportByName(n); if (a) return a; }
                return null;
            },
        },
        setTimeout(fn, ms) { timers.push({ fn, ms }); return timers.length; },
        console,
    };

    /** Drains scheduled timers; callbacks may schedule more, so this runs up to `rounds` passes. */
    function runTimers(rounds) {
        for (let r = 0; r < (rounds === undefined ? 1 : rounds); r++) {
            const due = timers.splice(0, timers.length);
            if (due.length === 0) return r;
            for (const t of due) t.fn();
        }
        return rounds;
    }

    /** Invokes every callback attached at `addr`, as the instrumented function being called. */
    function fire(addr, args, retval) {
        const cbs = attached.get(addr.addr) || [];
        for (const cb of cbs) {
            const self = {};
            if (cb.onEnter) cb.onEnter.call(self, args);
            if (cb.onLeave) cb.onLeave.call(self, retval === undefined ? new P(1) : retval);
        }
        return cbs.length;
    }

    const api = {
        P, MEM, alloc, allocStr, allocStdString, makeModule, env, messages, attached, timers,
        modules, fire, runTimers,
        int: (n) => new P(n),
        logs: (re) => messages.filter((m) => m.payload.type === 'log' && re.test(m.payload.msg || '')),
        ofType: (t) => messages.filter((m) => m.payload.type === t),
        clear: () => { messages.length = 0; },
        stats: () => ({ enumExportCalls, enumSymbolCalls }),
        resetStats: () => { enumExportCalls = 0; enumSymbolCalls = 0; },
    };
    return api;
}

module.exports = { createEnv };
