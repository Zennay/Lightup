/* PRIVATE byte-exact original source recovery. Offline store-only ZIP; never a grant or authentic client identity. */
(()=>{
'use strict';
const H=window.LightUpHistory,$=id=>document.getElementById(id);
const utf8=new TextEncoder(),fields=['finding_id','title','severity','retest_status','remediation'];
const toHex=b=>Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,'0')).join('');
function bytes64(s,max){
 if(typeof s!=='string'||s.length>Math.ceil(max/3)*4+8||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s))
   throw Error('HOLD: source original bytes have invalid base64 encoding.');
 const result=Uint8Array.from(atob(s),c=>c.charCodeAt(0));
 if(!result.length||result.length>max)throw Error('HOLD: exact original CSV exceeds 1 MiB.');
 let canonical='';for(let i=0;i<result.length;i+=32768)canonical+=String.fromCharCode(...result.subarray(i,i+32768));
 if(btoa(canonical)!==s)throw Error('HOLD: noncanonical original byte representation.');
 return result;
}
const crcTable=Array.from({length:256},(_,i)=>{
 let x=i;for(let j=0;j<8;j++)x=(x&1)?0xedb88320^(x>>>1):x>>>1;
 return x>>>0;
});
function crc32(data){let c=0xffffffff;for(const b of data)c=crcTable[(c^b)&255]^(c>>>8);return (c^0xffffffff)>>>0;}
function localHeader(name,size,crc){
 const bytes=utf8.encode(name),d=new Uint8Array(30+bytes.length),v=new DataView(d.buffer);
 v.setUint32(0,0x04034b50,true);v.setUint16(4,20,true);
 v.setUint16(6,0,true);v.setUint16(8,0,true);
 v.setUint16(10,0,true);v.setUint16(12,0x0021,true); // fixed 1980-01-01 DOS date
 v.setUint32(14,crc,true);v.setUint32(18,size,true);v.setUint32(22,size,true);
 v.setUint16(26,bytes.length,true);v.setUint16(28,0,true);
 d.set(bytes,30);return d;
}
function centralHeader(name,size,crc,offset){
 const bytes=utf8.encode(name),d=new Uint8Array(46+bytes.length),v=new DataView(d.buffer);
 v.setUint32(0,0x02014b50,true);v.setUint16(4,20,true);v.setUint16(6,20,true);
 v.setUint16(8,0,true);v.setUint16(10,0,true);
 v.setUint16(12,0,true);v.setUint16(14,0x0021,true); // matching fixed DOS date
 v.setUint32(16,crc,true);v.setUint32(20,size,true);v.setUint32(24,size,true);
 v.setUint16(28,bytes.length,true);v.setUint16(30,0,true);v.setUint16(32,0,true);
 v.setUint16(34,0,true);v.setUint16(36,0,true);v.setUint32(38,0,true);
 v.setUint32(42,offset,true);d.set(bytes,46);return d;
}
function zip(entries){
 if(!entries.length||entries.length>H.limits.maxSnapshots+1)
   throw Error('HOLD: invalid number of original-source recovery entries.');
 const names=new Set(),parts=[],centrals=[];let offset=0,centralSize=0;
 for(const [name,data] of entries){
  if(typeof name!=='string'||!/^(?:revision-[0-9]{2}-[0-9a-f]{12}\.csv|PRIVATE-source-manifest\.json)$/.test(name)||names.has(name)||!(data instanceof Uint8Array)||!data.length||data.length>2097152)
   throw Error('HOLD: ambiguous original-source ZIP entry.');
  names.add(name);const crc=crc32(data),local=localHeader(name,data.length,crc),central=centralHeader(name,data.length,crc,offset);
  if(offset+local.length+data.length>24000000)throw Error('HOLD: PRIVATE source recovery ZIP exceeds byte bounds.');
  parts.push(local,data);centrals.push(central);offset+=local.length+data.length;centralSize+=central.length;
 }
 const end=new Uint8Array(22),v=new DataView(end.buffer);
 v.setUint32(0,0x06054b50,true);v.setUint16(4,0,true);v.setUint16(6,0,true);
 v.setUint16(8,entries.length,true);v.setUint16(10,entries.length,true);
 v.setUint32(12,centralSize,true);v.setUint32(16,offset,true);v.setUint16(20,0,true);
 return new Blob([...parts,...centrals,end],{type:'application/zip'});
}
function status(t,err=false){$('message').textContent=t;$('message').className=err?'error':'info';}
async function exportSources(){
 if(!crypto?.subtle)throw Error('Secure local SHA-256 is required to recover original files.');
 // H.capture() requires exact current independently acknowledged human source and PRIVATE export.
 const p=H.capture(),currentSource=H.view();
 if(!p.snapshots.length||p.snapshots.length>H.limits.maxSnapshots)
  throw Error('Import a bounded original-source workspace first.');
 if(!confirm('Create ONE UNENCRYPTED PRIVATE ZIP containing byte-exact original CSV exports, their names and original source hashes? Preserve it only in an independently approved private destination. Nothing is sent.'))return;
 const entries=[],manifest={format:'LightUp original PRIVATE source recovery ZIP',version:1,
  disposition:'UNVERIFIED_ORIGINAL_SOURCE_EXPORT_RECOVERY',authenticated:false,
  source_authorized:false,client_consent:false,operator_consent:false,grant:false,execution:false,
  verified_retest:false,release:false,client_label:p.context.client,engagement_label:p.context.engagement,
  export_count:p.snapshots.length,sources:[]};
 for(let i=0;i<p.snapshots.length;i++){
  const s=p.snapshots[i],b=bytes64(s.csvBase64,H.limits.maxBytes);
  const byteHash=toHex(await crypto.subtle.digest('SHA-256',b));
  const text=new TextDecoder('utf-8',{fatal:true}).decode(b);
  const parsed=LightUpCasework.parseCSV(text),canonical=await LightUpCasework.digest(parsed);
  if(byteHash!==s.fileHash||canonical!==s.sourceHash||!currentSource[i]||
     currentSource[i].sourceHash!==s.sourceHash||currentSource[i].fileHash!==s.fileHash||
     parsed.length!==s.findings.length||
     parsed.some((f,j)=>fields.some(k=>f[k]!==s.findings[j][k])))
    throw Error('HOLD: original CSV bytes, full five-field source rows, canonical digest or in-memory sequence differ. No recovery ZIP generated.');
  const filename='revision-'+String(i+1).padStart(2,'0')+'-'+s.fileHash.slice(0,12)+'.csv';
  entries.push([filename,b]);
  manifest.sources.push({revision_index:i+1,archive_csv_filename:filename,
   private_original_input_name:s.name,private_operator_label:s.label,
   original_file_byte_sha256:s.fileHash,original_canonical_source_sha256:s.sourceHash,
   original_five_column_rows:parsed.length});
 }
 if(p.revision!==H.revision()||p.context.client!==$('client').value.trim()||
    p.context.engagement!==$('engagement').value.trim())
   throw Error('HOLD: source revision or client/engagement changed while preparing PRIVATE original recovery; no file generated.');
 H.privateAllowed();
 entries.push(['PRIVATE-source-manifest.json',utf8.encode(JSON.stringify(manifest,null,2)+'\n')]);
 const blob=zip(entries);
 const url=URL.createObjectURL(blob),a=document.createElement('a');
 a.href=url;a.download='lightup-PRIVATE-byte-exact-original-sources.zip';a.click();
 setTimeout(()=>URL.revokeObjectURL(url),30000);
 status('Created PRIVATE offline ZIP with '+p.snapshots.length+' unchanged original CSV file(s) and exact SHA-256 manifest. Not encrypted; keep it only on approved PRIVATE storage. No source/auth/retest status changed.');
}
$('recoverOriginalSources').addEventListener('click',()=>{
 exportSources().catch(e=>status(e.message,true));
});
})();
