/* PRIVATE original-source recovery ZIP import: exact-byte offline restoration only.
 * Deliberately accepts the narrow store-only ZIP emitted by this Studio, never an
 * arbitrary ZIP format, nested paths, scanners, grants or security results. */
(()=>{
'use strict';
const H=window.LightUpHistory,$=id=>document.getElementById(id),ENC=new TextEncoder(),DEC=new TextDecoder('utf-8',{fatal:true});
const KEYS=['finding_id','title','severity','retest_status','remediation'];
const MAX=25000000,MAX_CSV=1048576,MAX_MANIFEST=50000;
const hashRe=/^[a-f0-9]{64}$/,entryRe=/^revision-(\d{2})-([a-f0-9]{12})\.csv$/;
const equalKeys=(o,fields)=>!!o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join('|')===fields.slice().sort().join('|');
const hex=async b=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',b))].map(x=>x.toString(16).padStart(2,'0')).join('');
const crcTable=Array.from({length:256},(_,i)=>{let x=i;for(let j=0;j<8;j++)x=x&1?0xedb88320^(x>>>1):x>>>1;return x>>>0;});
const crc32=b=>{let x=0xffffffff;for(const c of b)x=crcTable[(x^c)&255]^(x>>>8);return (x^0xffffffff)>>>0;};
const say=(s,bad=false)=>{const el=$('message');el.textContent=s;el.className=bad?'error':'info';};
const b64=b=>{let out='';for(let i=0;i<b.length;i+=32768)out+=String.fromCharCode(...b.subarray(i,i+32768));return btoa(out);};
function unpack(raw){
 if(!(raw instanceof Uint8Array)||raw.length<22||raw.length>MAX)throw Error('HOLD: PRIVATE source recovery ZIP is outside supported size bounds.');
 const d=new DataView(raw.buffer,raw.byteOffset,raw.byteLength),n=raw.length;
 const u16=i=>{if(i<0||i+2>n)throw Error('HOLD: truncated ZIP field.');return d.getUint16(i,true);};
 const u32=i=>{if(i<0||i+4>n)throw Error('HOLD: truncated ZIP field.');return d.getUint32(i,true);};
 // No ZIP comments, ZIP64, split archives, data descriptors, compression or
 // extra fields. The original exporter writes a single deterministic format.
 const end=n-22;
 if(u32(end)!==0x06054b50||u16(end+4)!==0||u16(end+6)!==0||u16(end+20)!==0||
    u16(end+8)!==u16(end+10)||u16(end+10)<2||u16(end+10)>13)
  throw Error('HOLD: not a supported single-volume source recovery ZIP.');
 const count=u16(end+10),centralSize=u32(end+12),centralStart=u32(end+16);
 if(centralStart+centralSize!==end)throw Error('HOLD: ZIP central directory is missing, overlapping or ambiguous.');
 const names=new Map();let offset=centralStart,localNext=0;
 for(let i=0;i<count;i++){
  if(offset+46>end||u32(offset)!==0x02014b50||u16(offset+8)!==0||
     u16(offset+10)!==0||u16(offset+28)===0||u16(offset+30)!==0||
     u16(offset+32)!==0||u16(offset+34)!==0)
    throw Error('HOLD: unsupported ZIP entry type, compression, metadata or path.');
  const crc=u32(offset+16),compressed=u32(offset+20),plain=u32(offset+24),
        namelen=u16(offset+28),loc=u32(offset+42);
  if(compressed!==plain||!plain||plain>MAX_CSV||
     offset+46+namelen>end||loc!==localNext)
    throw Error('HOLD: overlapping, compressed or oversized original source ZIP entry.');
  const name=DEC.decode(raw.subarray(offset+46,offset+46+namelen));
  if(name!=='PRIVATE-source-manifest.json'&&!entryRe.test(name))
    throw Error('HOLD: unsupported original ZIP entry name or nested path.');
  if(names.has(name))throw Error('HOLD: duplicate source recovery ZIP entry.');
  if(loc+30>centralStart||u32(loc)!==0x04034b50||u16(loc+6)!==0||u16(loc+8)!==0||
     u16(loc+26)!==namelen||u16(loc+28)!==0||u32(loc+14)!==crc||
     u32(loc+18)!==plain||u32(loc+22)!==plain)
    throw Error('HOLD: local ZIP entry metadata conflicts with the central directory.');
  if(!raw.subarray(loc+30,loc+30+namelen).every((v,j)=>v===raw[offset+46+j]))
    throw Error('HOLD: original ZIP filenames disagree.');
  const start=loc+30+namelen,stop=start+plain;
  if(stop>centralStart)throw Error('HOLD: ZIP data overlaps another entry or directory.');
  const payload=raw.subarray(start,stop);
  if(crc32(payload)!==crc)throw Error('HOLD: original ZIP entry checksum does not match.');
  if(name==='PRIVATE-source-manifest.json'&&plain>MAX_MANIFEST)
    throw Error('HOLD: original source manifest exceeds PRIVATE size bounds.');
  names.set(name,payload);localNext=stop;offset+=46+namelen;
 }
 if(offset!==end||localNext!==centralStart||names.size!==count||
    !names.has('PRIVATE-source-manifest.json'))
  throw Error('HOLD: ZIP original source entries, directory or manifest are incomplete.');
 return names;
}
async function open(){
 if(!crypto?.subtle)throw Error('Secure browser SHA-256 is unavailable.');
 H.privateAllowed();
 if(!H.empty())throw Error('HOLD: Forget existing original source and HUMAN notes before restoring another PRIVATE ZIP.');
 const file=$('recoverImportFile').files[0];
 if(!file||file.size<150||file.size>MAX)throw Error('Choose one PRIVATE original-source recovery ZIP under 25 MB.');
 const revision=H.revision(),client=$('client').value.trim(),engagement=$('engagement').value.trim();
 if(!$('recoverImportAck').checked)throw Error('Acknowledge separate original client/engagement confirmation and local-only source review.');
 const archive=unpack(new Uint8Array(await file.arrayBuffer()));
 const manifestRaw=DEC.decode(archive.get('PRIVATE-source-manifest.json'));
 const manifest=JSON.parse(manifestRaw);
 const manifestFields=['format','version','disposition','authenticated','source_authorized','client_consent','operator_consent','grant','execution','verified_retest','release','client_label','engagement_label','export_count','sources'];
 if(!equalKeys(manifest,manifestFields)||manifestRaw!==JSON.stringify(manifest,null,2)+'\n'||
    manifest.format!=='LightUp original PRIVATE source recovery ZIP'||manifest.version!==1||
    manifest.disposition!=='UNVERIFIED_ORIGINAL_SOURCE_EXPORT_RECOVERY'||
    ['authenticated','source_authorized','client_consent','operator_consent','grant','execution','verified_retest','release'].some(k=>manifest[k]!==false)||
    manifest.client_label!==client||manifest.engagement_label!==engagement||
    !Array.isArray(manifest.sources)||manifest.sources.length<1||manifest.sources.length>H.limits.maxSnapshots||
    manifest.export_count!==manifest.sources.length||archive.size!==manifest.sources.length+1)
   throw Error('HOLD: original-source manifest violates context, completeness or false-only authority contract.');
 const snapshots=[],known=new Set();
 for(let i=0;i<manifest.sources.length;i++){
  const item=manifest.sources[i],required=['revision_index','archive_csv_filename','private_original_input_name','private_operator_label','original_file_byte_sha256','original_canonical_source_sha256','original_five_column_rows'];
  if(!equalKeys(item,required)||item.revision_index!==i+1||
     typeof item.archive_csv_filename!=='string'||!entryRe.test(item.archive_csv_filename)||
     typeof item.private_original_input_name!=='string'||item.private_original_input_name.length>160||
     typeof item.private_operator_label!=='string'||!item.private_operator_label.trim()||item.private_operator_label.length>100||
     !hashRe.test(item.original_file_byte_sha256)||!hashRe.test(item.original_canonical_source_sha256)||
     item.archive_csv_filename!=='revision-'+String(i+1).padStart(2,'0')+'-'+item.original_file_byte_sha256.slice(0,12)+'.csv'||
     !Number.isSafeInteger(item.original_five_column_rows)||item.original_five_column_rows<1||item.original_five_column_rows>H.limits.maxRows||
     known.has(item.original_canonical_source_sha256))
    throw Error('HOLD: noncanonical, duplicated or incomplete original source revision manifest.');
  known.add(item.original_canonical_source_sha256);
  const data=archive.get(item.archive_csv_filename);
  if(!data||!data.length||data.length>H.limits.maxBytes||
     await hex(data)!==item.original_file_byte_sha256)
    throw Error('HOLD: byte-exact original CSV is missing or original file hash differs.');
  const findings=LightUpCasework.parseCSV(DEC.decode(data));
  if(findings.length!==item.original_five_column_rows||
     await LightUpCasework.digest(findings)!==item.original_canonical_source_sha256)
    throw Error('HOLD: original five-column CSV content and canonical source digest disagree.');
  snapshots.push({name:item.private_original_input_name,label:item.private_operator_label,
    sourceHash:item.original_canonical_source_sha256,fileHash:item.original_file_byte_sha256,
    csvBase64:b64(data),findings});
 }
 if(H.revision()!==revision||!H.empty()||client!==$('client').value.trim()||engagement!==$('engagement').value.trim()||
    !$('recoverImportAck').checked)
  throw Error('HOLD: original source or independently declared context changed while restoring; nothing imported.');
 H.privateAllowed();
 if(!confirm('Restore '+snapshots.length+' BYTE-EXACT original CSV revision(s) into EMPTY local HUMAN workspace? This never restores HUMAN notes, consent, verified fixes, grants or scans. All recovered source claims remain UNVERIFIED.'))return;
 if(H.revision()!==revision||!H.empty())throw Error('HOLD: browser workspace changed before committing restored original sources.');
 H.restore({context:{client,engagement},snapshots,notes:[],decisions:[],merges:[],holdReviews:[]},revision);
 say('Restored '+snapshots.length+' original five-column CSV revision(s) from PRIVATE ZIP with original exact-file and canonical SHA-256. No HUMAN notes, authorization or verified remediation imported.');
}
$('recoverImport').addEventListener('click',()=>open().catch(e=>say(e.message,true)));
})();
