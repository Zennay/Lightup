/* Strict bounded JSON for PRIVATE owner handoff; rejects duplicate object keys. */
(function(global){
'use strict';
const MAX_JSON=2097152;
function bytes(s){return new TextEncoder().encode(s).length;}
function fail(msg){throw Error(msg);}
function strictJSON(s){
 if(typeof s!=='string'||bytes(s)>MAX_JSON)fail('Private draft exceeds 2 MiB.');
 let i=0,nodes=0; const ws=()=>{while(i<s.length&&/[\x20\t\r\n]/.test(s[i]))i++;};
 function str(){
  const start=i;if(s[i++]!=='"')fail('Expected JSON string.');
  while(i<s.length){const c=s[i++];
   if(c==='"')return JSON.parse(s.slice(start,i));
   if(c==='\\'){const e=s[i++];if(e==='u'){if(!/^[a-fA-F0-9]{4}$/.test(s.slice(i,i+4)))fail('Bad Unicode escape.');i+=4;}else if(!'"\\/bfnrt'.includes(e))fail('Invalid JSON escape.');}
   else if(c.charCodeAt(0)<32)fail('Unescaped control character.');
  }fail('Unclosed JSON string.');
 }
 function read(depth){
  if(++nodes>50000||depth>40)fail('JSON structure exceeds bounds.');
  ws();let c=s[i];
  if(c==='"')return str();
  if(c==='{'){i++;const o=Object.create(null),seen=new Set();ws();if(s[i]==='}'){i++;return o;}
   while(true){ws();const k=str();if(seen.has(k))fail('Duplicate JSON property.');seen.add(k);ws();if(s[i++]!==':')fail('Expected JSON colon.');o[k]=read(depth+1);ws();if(s[i]==='}'){i++;return o;}if(s[i++]!==',')fail('Expected JSON comma.');}
  }
  if(c==='['){i++;const a=[];ws();if(s[i]===']'){i++;return a;}
   while(true){a.push(read(depth+1));ws();if(s[i]===']'){i++;return a;}if(s[i++]!==',')fail('Expected array comma.');}
  }
  for(const [word,val] of [['true',true],['false',false],['null',null]])if(s.startsWith(word,i)){i+=word.length;return val;}
  const m=s.slice(i).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);if(m){i+=m[0].length;const v=Number(m[0]);if(!Number.isFinite(v))fail('Invalid JSON number.');return v;}
  fail('Invalid JSON value.');
 }
 const v=read(0);ws();if(i!==s.length)fail('Trailing JSON data.');return v;
}

global.LightUpOwnerPrivateJson=Object.freeze({read:strictJSON});
})(window);
