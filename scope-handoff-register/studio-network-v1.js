/* LightUp local proposal planning only. Never grants permission or calls a network API. */
(function(global) {
'use strict';
const IPV4_BITS=32n, IPV6_BITS=128n;
const dec=/^(?:0|[1-9]\d*)$/;
function parse4(host) {
 const words=host.split('.');
 if(words.length!==4 || !words.every(w=>dec.test(w)&&w.length<=3&&Number(w)<=255))return null;
 return words.reduce((n,w)=>(n<<8n)|BigInt(w),0n);
}
function parse6(host){
 if(!host.includes(':')||!/^[0-9a-f:]+$/i.test(host))return null;
 const chunks=host.split('::');
 if(chunks.length>2)return null;
 const group=(s)=>s ? s.split(':') : [];
 const left=group(chunks[0]),right=chunks.length===2?group(chunks[1]):[];
 const good=words=>words.every(w=>/^[0-9a-f]{1,4}$/i.test(w));
 if(!good(left)||!good(right))return null;
 const missing=8-left.length-right.length;
 if(chunks.length===2 ? missing<1 : missing!==0)return null;
 const words=[...left,...Array(missing).fill('0'),...right];
 if(words.length!==8)return null;
 return words.reduce((n,w)=>(n<<16n)|BigInt(parseInt(w,16)),0n);
}
function parse(value) {
 if(typeof value!=='string'||!value.trim()||value.length>253||value.trim()!==value)return null;
 const bits=value.split('/');
 if(bits.length>2)return null;
 let address=null,family=null,max=IPV4_BITS;
 const four=parse4(bits[0]);
 if(four!==null){address=four;family='ipv4';}
 else {
   const six=parse6(bits[0]);
   if(six!==null){address=six;family='ipv6';max=IPV6_BITS;}
 }
 if(family!==null) {
   if(bits.length===2 && (!dec.test(bits[1])||bits[1].length>3))return null;
   const prefix=bits.length===2?BigInt(bits[1]):max;
   if(prefix>max)return null;
   const hostBits=max-prefix, hostMask=(1n<<hostBits)-1n;
   const start=address&(((1n<<max)-1n)^hostMask);
   // Do not silently widen e.g. 192.0.2.17/24 to 192.0.2.0/24.
   if(bits.length===2 && start!==address)return null;
   const end=start+hostMask;
   return {raw:value,family,start,end,prefix:Number(prefix),canonical:family+':'+start.toString()+':'+prefix.toString(),isRange:prefix<max};
 }
 if(bits.length!==1)return null;
 if(value.length>253||!value.includes('.')||value.endsWith('.')||value.includes('..'))return null;
 if(!value.split('.').every(part=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(part)))return null;
 if(/^\d+(?:\.\d+){3}$/.test(value))return null;
 return {raw:value,family:'hostname',canonical:'hostname:'+value.toLowerCase(),isRange:false};
}
function overlaps(a,b){
 if(!a||!b||a.family!==b.family)return false;
 if(a.family==='hostname')return a.canonical===b.canonical;
 return a.start<=b.end && b.start<=a.end;
}
function contains(a,b){
 if(!a||!b||a.family!==b.family)return false;
 if(a.family==='hostname')return a.canonical===b.canonical;
 return a.start<=b.start && a.end>=b.end;
}
function mergeIntervals(items,family){
 const sorted=items.filter(a=>a&&a.family===family).map(a=>({start:a.start,end:a.end})).sort((a,b)=>a.start<b.start?-1:a.start>b.start?1:0);
 const merged=[];
 for(const a of sorted){
   const prev=merged[merged.length-1];
   if(prev && a.start<=prev.end+1n){if(a.end>prev.end)prev.end=a.end;}
   else merged.push({...a});
 }
 return merged;
}
function coveredBy(ranges,entry){
 if(!entry)return false;
 if(entry.family==='hostname')return ranges.some(a=>a&&a.canonical===entry.canonical);
 return mergeIntervals(ranges,entry.family).some(a=>a.start<=entry.start&&a.end>=entry.end);
}
function inspect(included,excluded){
 const out=[],inScope=included.map(parse),outScope=excluded.map(parse);
 const warn=(level,code,message)=>out.push({level,code,message});
 for(const [kind,items,parsed] of [['Included',included,inScope],['Excluded',excluded,outScope]]){
   if(items.length>80)warn('error','too_many',kind+' assets exceed 80 items.');
   const seen=new Set();
   items.forEach((item,i)=>{
     const id=parsed[i];
     if(!id){warn('error','invalid',kind+': invalid host/IP/CIDR '+item.slice(0,80));return;}
     if(seen.has(id.canonical))warn('error','duplicate',kind+': duplicate/canonical alias '+item.slice(0,80));
     seen.add(id.canonical);
     if((id.family==='ipv4'||id.family==='ipv6')&&id.prefix===0)warn('warning','global_range',kind+': whole-address-space CIDR '+item+' requires explicit narrowing.');
     if(id.family==='ipv6')warn('warning','ipv6',kind+': IPv6 zone/alias and ownership handling require independent authority verification.');
   });
 }
 for(let i=0;i<inScope.length;i++){
   for(let j=i+1;j<inScope.length;j++){
     if(overlaps(inScope[i],inScope[j])&&inScope[i].canonical!==inScope[j].canonical)
       warn('warning','included_overlap','Proposed entries may overlap: '+included[i]+' / '+included[j]);
   }
   for(let j=0;j<outScope.length;j++){
     if(overlaps(inScope[i],outScope[j]))warn('warning','exclusion_overlap','Proposed and excluded entries overlap: '+included[i]+' / '+excluded[j]+' (requires precise operator enforcement).');
   }
 }
 return out.slice(0,100);
}
function expansion(before,after){
 const parsedBefore=before.map(parse),parsedAfter=after.map(parse);
 const added=parsedAfter.filter(a=>a&&!coveredBy(parsedBefore,a)).map(a=>a.raw);
 const removed=parsedBefore.filter(a=>a&&!coveredBy(parsedAfter,a)).map(a=>a.raw);
 return {added,removed,unparsed:parsedAfter.some(a=>a===null)||parsedBefore.some(a=>a===null),
   caveat:'Addresses and CIDR ranges only; DNS, exclusions, asset ownership and independent authorization are not evaluated.'};
}

/* Interval arithmetic for UI planning only; no policy or execution decisions.
 * Subtract excluded IP/CIDR intervals before identifying effective shared address space.
 * Hostnames remain opaque literals, not DNS-resolved addresses. */
function subtractIntervals(base, holes){
 let current=base.map(a=>({start:a.start,end:a.end}));
 for(const h of holes){
  const next=[];
  for(const x of current){
   if(h.end<x.start||h.start>x.end){next.push(x);continue;}
   if(h.start>x.start)next.push({start:x.start,end:h.start-1n});
   if(h.end<x.end)next.push({start:h.end+1n,end:x.end});
  }
  current=next;
  if(!current.length)break;
 }
 return current;
}
function effectiveCoverage(included,excluded){
 if(!Array.isArray(included)||!Array.isArray(excluded)||included.length>80||excluded.length>80)return null;
 const allow=included.map(parse),deny=excluded.map(parse);
 if(allow.some(x=>!x)||deny.some(x=>!x))return null;
 const result={hostname:new Set(),ipv4:[],ipv6:[]};
 const deniedHost=new Set(deny.filter(a=>a.family==='hostname').map(a=>a.canonical));
 for(const a of allow){
  if(a.family==='hostname'&&!deniedHost.has(a.canonical))result.hostname.add(a.canonical);
 }
 for(const family of ['ipv4','ipv6']){
  const allowed=mergeIntervals(allow,family);
  const holes=mergeIntervals(deny,family);
  result[family]=allowed.flatMap(a=>subtractIntervals([a],holes));
 }
 return result;
}
function coverageOverlap(a,b){
 if(!a||!b)return false;
 for(const h of a.hostname)if(b.hostname.has(h))return true;
 for(const family of ['ipv4','ipv6']){
  for(const x of a[family])for(const y of b[family])
   if(x.start<=y.end&&y.start<=x.end)return true;
 }
 return false;
}
function coverageDifference(base,updated){
 if(!base||!updated)return null;
 const added=[],removed=[];
 for(const family of ['ipv4','ipv6']){
  for(const x of updated[family])added.push(...subtractIntervals([x],base[family]).map(y=>({family,start:y.start.toString(),end:y.end.toString()})));
  for(const x of base[family])removed.push(...subtractIntervals([x],updated[family]).map(y=>({family,start:y.start.toString(),end:y.end.toString()})));
 }
 for(const host of updated.hostname)if(!base.hostname.has(host))added.push({family:'hostname',asset:host.slice(9)});
 for(const host of base.hostname)if(!updated.hostname.has(host))removed.push({family:'hostname',asset:host.slice(9)});
 return {added:added.slice(0,160),removed:removed.slice(0,160),
  truncated:added.length>160||removed.length>160,
  caveat:'Non-authorizing, local exact hostname and numeric IP interval hints. DNS and ownership are never inspected.'};
}


function addressText(family,integer){
 if(family==='ipv4'){
  const items=[];
  for(let shift=24n;shift>=0n;shift-=8n)items.push(Number((integer>>shift)&255n));
  return items.join('.');
 }
 if(family!=='ipv6')return null;
 const words=[];
 for(let shift=112n;shift>=0n;shift-=16n)words.push(Number((integer>>shift)&65535n).toString(16));
 // RFC 5952 longest leftmost zero compression; presentation only, not authority.
 let bestStart=-1,bestLength=1;
 for(let i=0;i<8;){
  if(words[i]!=='0'){i++;continue;}
  let j=i;while(j<8&&words[j]==='0')j++;
  if(j-i>bestLength){bestStart=i;bestLength=j-i;}
  i=j;
 }
 if(bestStart<0)return words.join(':');
 const left=words.slice(0,bestStart).join(':'),right=words.slice(bestStart+bestLength).join(':');
 return left+'::'+right;
}
function describeEffective(included,excluded,maxRows=180){
 if(!Number.isSafeInteger(maxRows)||maxRows<1||maxRows>300)return null;
 const coverage=effectiveCoverage(included,excluded);
 if(!coverage)return null;
 const groups=[],total={ipv4:'0',ipv6:'0',hostnames:String(coverage.hostname.size)};
 let truncated=false;
 for(const family of ['ipv4','ipv6']){
  const bits=family==='ipv4'?32:128;
  let count=0n;
  for(const span of coverage[family]){
   count+=span.end-span.start+1n;
   let current=span.start;
   while(current<=span.end){
    if(groups.length>=maxRows){truncated=true;break;}
    let size=1n,aligned=0;
    while(aligned<bits && (current&((size<<1n)-1n))===0n){size<<=1n;aligned++;}
    while(size>span.end-current+1n){size>>=1n;aligned--;}
    groups.push({family,asset:addressText(family,current)+'/'+(bits-aligned),
      start:addressText(family,current),end:addressText(family,current+size-1n),
      address_count:size.toString()});
    current+=size;
   }
  }
  total[family]=count.toString();
 }
 const hostnames=[...coverage.hostname].map(h=>h.slice('hostname:'.length)).sort();
 return {status:'REVIEW_ONLY',total,groups,hostnames,truncated,
  warning:'Offline numerical preview after text-declared exclusions; does not resolve DNS, authenticate ownership, prove grant scope, evaluate authorization or permit execution.'};
}

global.LightUpScopeNetwork=Object.freeze({parse,overlaps,contains,inspect,expansion,effectiveCoverage,coverageOverlap,coverageDifference,addressText,describeEffective});
})(window);
