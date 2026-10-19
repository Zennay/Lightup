/* Original PRIVATE Casework v1 import; strictly local, non-authorizing. */
(()=>{
'use strict';
const $=id=>document.getElementById(id),H=window.LightUpHistory;
const MAX=2097152;
function status(message,fail=false){$('message').textContent=message;$('message').className=fail?'error':'info';}
/* Bounded JSON grammar parser that rejects duplicate keys at every depth, including escaped aliases. */
function uniqueJSON(raw){
 if(typeof raw!=='string'||raw.length>MAX||!raw.length)throw Error('Unsupported PRIVATE original Casework JSON size.');
 let i=0,nodes=0;
 const ws=()=>{while(i<raw.length&&/[\x20\t\r\n]/.test(raw[i]))i++;};
 function str(){
  if(raw[i]!=='"')throw Error('Expected canonical JSON string.');
  const start=i++;let ended=false;
  while(i<raw.length){
   const c=raw[i++];
   if(c==='"'){ended=true;break;}
   if(c==='\\'){if(i>=raw.length)break;i++;}
  }
  if(!ended)throw Error('Unclosed JSON string.');
  return JSON.parse(raw.slice(start,i));
 }
 function value(depth){
  if(++nodes>100000||depth>20)throw Error('PRIVATE Casework nesting/structure exceeds accepted limits.');
  ws();const ch=raw[i];
  if(ch==='{'){
   i++;ws();const obj=Object.create(null),seen=new Set();
   if(raw[i]==='}'){i++;return obj;}
   while(true){
    ws();const key=str();if(seen.has(key))throw Error('Duplicate JSON object key: original Casework HOLD.');seen.add(key);
    ws();if(raw[i++]!==':')throw Error('Expected JSON property separator.');
    obj[key]=value(depth+1);ws();
    if(raw[i]==='}'){i++;break;}
    if(raw[i++]!==',')throw Error('Expected JSON object separator.');
   }return obj;
  }
  if(ch==='['){
   i++;ws();const a=[];if(raw[i]===']'){i++;return a;}
   while(true){a.push(value(depth+1));ws();if(raw[i]===']'){i++;break;}if(raw[i++]!==',')throw Error('Expected JSON list separator.');}
   return a;
  }
  if(ch==='"')return str();
  const start=i;
  while(i<raw.length&&!/[\s,\]}]/.test(raw[i]))i++;
  const t=raw.slice(start,i);
  if(!/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+\-]?\d+)?)$/.test(t))throw Error('Unsupported JSON literal.');
  return JSON.parse(t);
 }
 const result=value(0);ws();if(i!==raw.length)throw Error('Trailing or malformed JSON content.');
 return result;
}
async function load(){
 const file=$('nativeCaseworkFile').files[0];
 if(!file||file.size===0||file.size>MAX)throw Error('Select original PRIVATE Casework v1 JSON of 2 MiB or less.');
 if(!H.view().length)throw Error('Import the exact original source CSV first.');
 H.privateAllowed();
 const revision=H.revision();
 const raw=await file.text(),packet=uniqueJSON(raw);
 if(H.revision()!==revision)throw Error('Original source or HUMAN notes changed while loading; no mutation.');
 const needsOverwrite=H.noteSummary();
 const allow=$('replaceHumanNotes').checked;
 if((needsOverwrite.bound+needsOverwrite.held)>0){
  if(!allow)throw Error('Existing notes stay unchanged. Acknowledge replacement of all existing private HUMAN notes to import original Casework.');
  if(!window.confirm('PRIVATE HUMAN DATA: Replace all current in-memory HUMAN notes with original source-matched Casework v1 notes? Export an encrypted checkpoint first to preserve old notes. No security permission or verdict is granted.'))return;
 }
 const outcome=H.importCasework(packet,revision,allow);
 status('Imported '+outcome.imported+' HUMAN Casework records for exact current original source ('+outcome.original+' findings). Original Casework statuses and blockers are unverified human statements; no scan/retest/authorization.');
 $('nativeCaseworkFile').value='';$('replaceHumanNotes').checked=false;
}
$('nativeImport').addEventListener('click',()=>load().catch(e=>status(e.message,true)));
})();
