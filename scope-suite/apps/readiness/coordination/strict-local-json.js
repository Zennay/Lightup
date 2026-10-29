/* Strict bounded JSON duplicate-key gate for local LightUp draft imports.
 * This is NOT a verifier of source authenticity, approval, ownership or grant.
 * This scanner only detects ambiguous names before native JSON.parse.
 */
(function(global){
'use strict';
function parse(text){
 if(typeof text!=='string'||text.length>262144)throw Error('JSON source exceeds local parser limit.');
 let i=0;
 const len=text.length, MAX_DEPTH=40;
 function space(){while(i<len&&(/\s/.test(text[i])))i++;}
 function stringToken(){
  if(text[i]!=='"')throw Error('Expected JSON key/string.');
  const start=i++;
  let closed=false;
  while(i<len){
   const ch=text[i++];
   if(ch==='"'){closed=true;break;}
   if(ch==='\\'){
    if(i>=len)throw Error('Truncated JSON escape.');
    if(text[i]==='u'){
     i++;
     if(i+4>len)throw Error('Truncated JSON Unicode escape.');
     i+=4;
    }else i++;
   }
  }
  if(!closed)throw Error('Unterminated JSON string.');
  // Native parser handles strict JSON escapes and canonical decoded key equality.
  return JSON.parse(text.slice(start,i));
 }
 function value(depth){
  if(depth>MAX_DEPTH)throw Error('JSON nesting exceeds safe limit.');
  space();
  if(i>=len)throw Error('Incomplete JSON value.');
  const ch=text[i];
  if(ch==='"'){stringToken();return;}
  if(ch==='{'){object(depth+1);return;}
  if(ch==='['){array(depth+1);return;}
  const start=i;
  while(i<len&&!/[,}\]\s]/.test(text[i]))i++;
  if(i===start)throw Error('Incomplete JSON literal.');
  // Validate the complete primitive later using JSON.parse.
 }
 function object(depth){
  if(depth>MAX_DEPTH)throw Error('JSON object nesting exceeds safe limit.');
  i++;space();
  const names=new Set();
  if(text[i]==='}'){i++;return;}
  while(i<len){
   space();
   const key=stringToken();
   if(key==='__proto__'||key==='constructor'||key==='prototype')
    throw Error('Unsafe reserved JSON property.');
   if(names.has(key))throw Error('Ambiguous duplicate JSON property: '+key.slice(0,70));
   names.add(key);
   space();if(text[i++]!==':')throw Error('Expected JSON object colon.');
   value(depth);space();
   const sep=text[i++];
   if(sep==='}')return;
   if(sep!==',')throw Error('Expected JSON object separator.');
  }
  throw Error('Incomplete JSON object.');
 }
 function array(depth){
  if(depth>MAX_DEPTH)throw Error('JSON array nesting exceeds safe limit.');
  i++;space();
  if(text[i]===']'){i++;return;}
  while(i<len){
   value(depth);space();
   const sep=text[i++];
   if(sep===']')return;
   if(sep!==',')throw Error('Expected JSON array separator.');
  }
  throw Error('Incomplete JSON array.');
 }
 value(0);space();
 if(i!==len)throw Error('Unexpected trailing JSON bytes.');
 const parsed=JSON.parse(text);
 if(!parsed||typeof parsed!=='object'||Array.isArray(parsed))throw Error('JSON root must be an object.');
 return parsed;
}
global.LightUpStrictJSON=Object.freeze({parse});
})(window);
