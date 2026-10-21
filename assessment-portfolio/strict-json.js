"use strict";
/* Shared duplicate-key rejecting JSON admission for private offline HUMAN restores. */
(() => {
  const reject = () => { throw new Error("Invalid JSON or duplicate object key"); };
  function parse(raw, maxBytes = 4194304) {
    if (typeof raw !== "string" || new TextEncoder().encode(raw).length > maxBytes) reject();
    let pos = 0;
    const ws = () => {
      while (pos < raw.length && [0x20,0x09,0x0a,0x0d].includes(raw.charCodeAt(pos))) pos++;
    };
    const string = () => {
      const start = pos;
      if (raw[pos++] !== '"') reject();
      while (pos < raw.length) {
        const ch = raw[pos];
        if (ch === '"') { pos++; return JSON.parse(raw.slice(start,pos)); }
        if (ch === "\\") {
          pos++;
          if (pos >= raw.length) reject();
          if (raw[pos] === "u") {
            if (!/^[0-9a-fA-F]{4}$/.test(raw.slice(pos+1,pos+5))) reject();
            pos += 5;
          } else {
            if (!'"\\/bfnrt'.includes(raw[pos])) reject();
            pos++;
          }
        } else {
          if (raw.charCodeAt(pos) < 0x20) reject();
          pos++;
        }
      }
      reject();
    };
    const value = () => {
      ws();
      const ch = raw[pos];
      if (ch === '"') return string();
      if (ch === "{") {
        pos++;
        ws();
        const out = {}, seen = new Set();
        if (raw[pos] === "}") { pos++; return out; }
        while (true) {
          ws();
          const key = string();
          if (seen.has(key)) reject();
          seen.add(key);
          ws();
          if (raw[pos++] !== ":") reject();
          Object.defineProperty(out,key,{value:value(),enumerable:true,writable:true,configurable:true});
          ws();
          if (raw[pos] === "}") { pos++; return out; }
          if (raw[pos++] !== ",") reject();
        }
      }
      if (ch === "[") {
        pos++;
        ws();
        const out = [];
        if (raw[pos] === "]") { pos++; return out; }
        while (true) {
          out.push(value());
          ws();
          if (raw[pos] === "]") { pos++; return out; }
          if (raw[pos++] !== ",") reject();
        }
      }
      for (const [literal,result] of [["true",true],["false",false],["null",null]]) {
        if (raw.startsWith(literal,pos)) { pos += literal.length; return result; }
      }
      const match = raw.slice(pos).match(/^-?(?:0|[1-9][0-9]*)(?:[.][0-9]+)?(?:[eE][+-]?[0-9]+)?/);
      if (!match) reject();
      pos += match[0].length;
      const number = Number(match[0]);
      if (!Number.isFinite(number)) reject();
      return number;
    };
    const result = value();
    ws();
    if (pos !== raw.length) reject();
    return result;
  }
  Object.defineProperty(globalThis,"LightUpStrictJSON",{
    value:Object.freeze({parse}),configurable:false,writable:false
  });
})();
