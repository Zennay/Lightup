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
global.LightUpScopeNetwork=Object.freeze({parse,overlaps,contains,inspect,expansion});
})(window);
