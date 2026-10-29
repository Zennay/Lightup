/* LightUp offline handoff tray: untrusted local files, never authority or consent. */
"use strict";
(() => {
  const $ = id => document.getElementById(id);
  const MAX_ITEMS = 24, MAX_DOCUMENT_BYTES = 262144, MAX_SOURCE_BYTES = 65536;
  const MAX_TOTAL_BYTES = 2097152;
  const FALSE_KEYS = new Set([
    "authorization","client_consent","operator_consent","grant","execution",
    "revocation_checked","authenticated","authenticated_client","authenticated_operator",
    "consent_verified","grant_issued","authorized","scope_approved","risk_approved",
    "scan","scan_allowed","dispatch","dispatch_allowed","deploy","deploy_allowed",
    "release","release_allowed","execution_allowed","actual_revocation","actual_stop"
  ]);
  const SPECS = Object.freeze({
    "lightup.scope_proposal_draft":{label:"Studio v1 bronconcept",state:"DRAFT_ONLY",field:"state",route:["briefing","permission","schedule","handoff","readiness","withdrawal","vault"],source:true},
    "lightup.scope_briefing_handoff":{label:"Scope Briefing (onbevoegd)",state:"REVIEW_ONLY_HOLD",field:"state",route:[]},
    "lightup.scope_permission_brief":{label:"Ongeverifieerde Permission Brief",state:"REVIEW_ONLY_HOLD",field:"state",route:["permission"]},
    "lightup.scope_permission_reply_reconciliation":{label:"Ongeverifieerde gecombineerde antwoorden",state:"REVIEW_ONLY_HOLD",field:"disposition",route:["handoff"]},
    "lightup.scope_human_preparation_backup":{label:"Lokale menselijke voorbereiding",state:"REVIEW_ONLY_HOLD",field:"state",route:["permission"]},
    "lightup.scope_handoff_local_progress":{label:"Handoff-voortgang (lokaal)",state:"REVIEW_ONLY_HOLD",field:"state",route:["handoff"]},
    "lightup.scope_handoff_review_register":{label:"Handoff-reviewverslag",state:"REVIEW_ONLY_HOLD",field:"state",route:[]},
    "lightup.scope_withdrawal_review_only":{label:"STOP/Withdrawal-review (geen intrekking)",state:"REVIEW_ONLY",field:"disposition",route:["handoff"]},
    "lightup.scope_proposal_revision_preview":{label:"Scope-revisievoorstel (onbevoegd)",state:"REVIEW_ONLY_HOLD",field:"state",route:[]},
    "lightup.scope_native_intake_route":{label:"Intake-routevoorstel (onbevoegd)",state:"REVIEW_ONLY",field:"disposition",route:[]}
  });
  const ROUTE_URLS=Object.freeze({
    briefing:"apps/briefing/scope-briefing/standalone.html",
    permission:"apps/permission/scope-permission-brief/standalone.html",
    schedule:"apps/schedule/studio/scope-schedule-board.html",
    handoff:"apps/handoff/scope-handoff-register/standalone.html",
    readiness:"apps/readiness/coordination/scope-readiness-standalone.html",
    withdrawal:"apps/withdrawal/withdrawal-desk/standalone.html",
    vault:"apps/vault/scope-vault/standalone.html"
  });
  const ROUTE_NAMES=Object.freeze({
    briefing:"Scope Briefing",permission:"Permission Brief",schedule:"Planning",
    handoff:"Handoff Register",readiness:"Readiness",
    withdrawal:"Withdrawal Desk",vault:"Lokale Vault"
  });
  let documents = [];
  const isObject = x => x !== null && typeof x==="object" && !Array.isArray(x);
  const own = (x,k) => Object.prototype.hasOwnProperty.call(x,k);
  const shaPattern = /^[a-f0-9]{64}$/;

  // A bounded local decoder catches nested duplicate keys; plain JSON.parse alone cannot.
  function decodeStrict(str) {
    let index=0;
    const white=()=>{while(index<str.length && /[\x20\t\r\n]/.test(str[index]))index++;};
    function stringValue(){
      const from=index;
      if(str[index++]!=='"')throw Error("JSON_STRING");
      while(index<str.length){
        const char=str[index++];
        if(char==='"')return JSON.parse(str.slice(from,index));
        if(char==='\\') { if(index>=str.length)throw Error("JSON_ESCAPE"); index++; }
        else if(char.charCodeAt(0)<32)throw Error("JSON_CONTROL");
      }
      throw Error("JSON_STRING_END");
    }
    function value(depth) {
      if(depth>18)throw Error("JSON_DEPTH");
      white();
      if(str[index]==='"')return stringValue();
      if(str[index]==='{'){
        index++;
        const result=Object.create(null);
        white();
        if(str[index]==='}') {index++;return result;}
        let count=0;
        while(index<str.length){
          white();
          const key=stringValue();
          if(own(result,key))throw Error("JSON_DUPLICATE");
          if(++count>256)throw Error("JSON_FIELDS");
          white();if(str[index++]!==':')throw Error("JSON_COLON");
          result[key]=value(depth+1);
          white();
          const delimiter=str[index++];
          if(delimiter==='}')return result;
          if(delimiter!==',')throw Error("JSON_OBJECT");
        }
        throw Error("JSON_OBJECT_END");
      }
      if(str[index]==='['){
        index++;
        const result=[];
        white();if(str[index]===']'){index++;return result;}
        while(index<str.length){
          if(result.length>=128)throw Error("JSON_ITEMS");
          result.push(value(depth+1));
          white();
          const delimiter=str[index++];
          if(delimiter===']')return result;
          if(delimiter!==',')throw Error("JSON_ARRAY");
        }
        throw Error("JSON_ARRAY_END");
      }
      const match=/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(str.slice(index));
      if(!match)throw Error("JSON_VALUE");
      index+=match[0].length;
      return JSON.parse(match[0]);
    }
    const document=value(0);
    white();
    if(index!==str.length)throw Error("JSON_TRAILING");
    return document;
  }

  function falseAuthorityOnly(node,depth=0){
    if(depth>18)throw Error("TREE_DEPTH");
    if(typeof node==="number"&&!Number.isFinite(node))throw Error("INVALID_NUMBER");
    if(Array.isArray(node)){
      for(const entry of node)falseAuthorityOnly(entry,depth+1);
    } else if(isObject(node)){
      for(const [key,entry] of Object.entries(node)){
        // This is document triage, not an authentication verdict. Reject obvious elevated authority fields.
        if(FALSE_KEYS.has(key)&&entry!==false)throw Error("ELEVATED_AUTHORITY");
        falseAuthorityOnly(entry,depth+1);
      }
    }
  }

  function inspect(value) {
    if(!isObject(value)||typeof value.kind!=="string"||!own(SPECS,value.kind))
      throw Error("UNSUPPORTED_DOCUMENT");
    const spec=SPECS[value.kind];
    if(value[spec.field]!==spec.state)throw Error("UNTRUSTED_STATUS");
    const schema = value.schema_version === undefined ? value.version : value.schema_version;
    if(schema!==1 && !(value.kind==="lightup.scope_handoff_local_progress"&&[2,3,4,5].includes(schema)) &&
      !(value.kind==="lightup.scope_handoff_review_register"&&schema===3))
      throw Error("UNSUPPORTED_SCHEMA");
    falseAuthorityOnly(value);
    let sourceSHA=null;
    if(spec.source){
      if(!Array.isArray(value.requested_assets)||!Array.isArray(value.excluded_assets)||
        value.requested_assets.length>128||value.excluded_assets.length>128||
        value.requested_assets.some(x=>typeof x!=="string"||!x.trim())||
        value.excluded_assets.some(x=>typeof x!=="string"||!x.trim())||
        !Number.isInteger(value.requested_risk)||value.requested_risk<1||value.requested_risk>4||
        !["analysis_only","authorized_assessment"].includes(value.requested_mode))
        throw Error("INVALID_STUDIO_DRAFT");
      for(const key of ["authorization","client_consent","operator_consent","grant","execution","revocation_checked"])
        if(!own(value,key)||value[key]!==false)throw Error("STUDIO_NOT_DRAFT");
      const flags=["passive_analysis","configuration_review","private_lab_network_checks"];
      if(!isObject(value.proposed_activities)||
         Object.keys(value.proposed_activities).length!==3||
         flags.some(key=>!own(value.proposed_activities,key)||typeof value.proposed_activities[key]!=="boolean"))
        throw Error("INVALID_STUDIO_DRAFT");
      if(!own(value,"proposed_window_local")||
         !(value.proposed_window_local===null||isObject(value.proposed_window_local)))
        throw Error("INVALID_STUDIO_DRAFT");
    } else if(own(value,"source_sha256")) {
      if(typeof value.source_sha256!=="string"||!shaPattern.test(value.source_sha256))
        throw Error("INVALID_SOURCE_HASH");
      sourceSHA=value.source_sha256;
    }
    return {
      kind:value.kind,label:spec.label,source:spec.source,sourceSHA,
      targets:spec.route, risk:spec.source?value.requested_risk:null,
      mode:spec.source?value.requested_mode:null,
      included:spec.source?value.requested_assets.length:null,
      excluded:spec.source?value.excluded_assets.length:null,
      hints:spec.source?null:Object.fromEntries(
        ["source_kind","requested_mode","requested_risk","proposed_assets_count","excluded_assets_count"]
          .filter(key=>own(value,key)).map(key=>[key,value[key]]))
    };
  }
  async function digest(bytes){
    if(!globalThis.crypto?.subtle)throw Error("NO_BROWSER_SHA256");
    const digest=await crypto.subtle.digest("SHA-256",bytes);
    return Array.from(new Uint8Array(digest),x=>x.toString(16).padStart(2,"0")).join("");
  }
  function detailMessage(code){
    const messages={
      FILE_TOO_LARGE:"Bestand groter dan de maximumgrootte.",
      NO_BROWSER_SHA256:"Deze browseromgeving biedt geen veilige lokale SHA-256. Import wordt geweigerd.",
      UNSUPPORTED_DOCUMENT:"Bestandssoort onbekend; het document wordt niet ingeladen.",
      UNTRUSTED_STATUS:"Document heeft geen verplichte DRAFT/HOLD-status.",
      ELEVATED_AUTHORITY:"Bestand bevat een bevoegdheidsveld dat niet letterlijk false is.",
      INVALID_STUDIO_DRAFT:"Studio-gegevens zijn onvolledig of ongeldig.",
      STUDIO_NOT_DRAFT:"Studio-bron bevat niet alle verplichte onware autorisatievelden.",
      INVALID_SOURCE_HASH:"Bron-SHA-256 is ongeldig.",
      UNSUPPORTED_SCHEMA:"Documentversie niet ondersteund."
    };
    return messages[code]||"Bestand geweigerd: ongeldige UTF-8, dubbelzinnige JSON of ontbrekende gegevens.";
  }
  function reportStatus(message,failed=false){
    $("tray-status").textContent=message;
    $("tray-status").classList.toggle("fail",failed);
  }
  async function parseFile(file){
    const cap=file.size;
    if(cap<=0 || cap>MAX_DOCUMENT_BYTES || !file.name.toLowerCase().endsWith(".json"))
      throw Error("FILE_TOO_LARGE");
    const bytes=new Uint8Array(await file.arrayBuffer());
    if(bytes[0]===0xef&&bytes[1]===0xbb&&bytes[2]===0xbf)throw Error("INVALID_BOM");
    const str=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
    const content=decodeStrict(str);
    const result=inspect(content);
    if(result.source && bytes.length>MAX_SOURCE_BYTES)throw Error("FILE_TOO_LARGE");
    const hash=await digest(bytes);
    return {...result,hash,bytes};
  }
  function originalFor(doc){
    return doc.sourceSHA===null?null:documents.find(other=>other.source&&other.hash===doc.sourceSHA)||null;
  }
  function attachedSource(doc){
    return originalFor(doc)!==null;
  }
  function mismatch(doc){
    const source=originalFor(doc), hints=doc.hints;
    if(!source||!hints)return false;
    const expected={
      source_kind:"lightup.scope_proposal_draft",
      requested_mode:source.mode,requested_risk:source.risk,
      proposed_assets_count:source.included,excluded_assets_count:source.excluded
    };
    return Object.entries(hints).some(([key,reported])=>reported!==expected[key]);
  }
  function summary(){
    const sources=documents.filter(x=>x.source).length;
    const linked=documents.filter(x=>!x.source&&attachedSource(x)).length;
    const unlinked=documents.filter(x=>x.sourceSHA&&!attachedSource(x)).length;
    const conflicts=documents.filter(x=>mismatch(x)).length;
    const high=documents.filter(x=>x.source&&x.risk===4).length;
    $("tray-summary").textContent=[sources+" originele Studio-documenten",linked+" gekoppelde bijlagen",unlinked+" ontbrekende bronnen",conflicts+" tegenstrijdige bronclaims",high+" risico-4 concepten"].join(" · ");
    $("tray-summary").classList.toggle("needs-attention",unlinked>0||conflicts>0||high>0);
  }
  function create(tag,cls,content){
    const el=document.createElement(tag);
    if(cls)el.className=cls;
    if(content!==undefined)el.textContent=content;
    return el;
  }
  function download(doc){
    const uri=URL.createObjectURL(new Blob([doc.bytes],{type:"application/json"}));
    const anchor=create("a");
    const slug=doc.kind.replace(/[^a-z0-9_.-]/g,"-").slice(0,55);
    anchor.href=uri;anchor.download=slug+"-"+doc.hash.slice(0,12)+".json";
    document.body.append(anchor);anchor.click();anchor.remove();
    setTimeout(()=>URL.revokeObjectURL(uri),1000);
  }
  function render(){
    const area=$("tray-list");
    area.replaceChildren();
    $("tray-count").textContent=documents.length+" / "+MAX_ITEMS;
    $("tray-empty").hidden=documents.length>0;
    $("tray-export").disabled=documents.length===0;
    $("tray-clear").disabled=documents.length===0;
    summary();
    for(let n=0;n<documents.length;n++){
      const doc=documents[n];
      const article=create("article","tray-item");
      const head=create("div","tray-item-head");
      const names=create("div");
      names.append(create("h3",null,doc.label));
      names.append(create("p","tray-meta","Document "+String(n+1).padStart(2,"0")+
        " · "+doc.bytes.length+" bytes · SHA-256 "+doc.hash.slice(0,20)+"…"));
      head.append(names);
      head.append(create("span","tray-pill",doc.source?"BRON / DRAFT":"REVIEW_ONLY"));
      article.append(head);
      if(doc.source){
        article.append(create("p","tray-detail",
          "Voorgesteld risico "+doc.risk+"/4 · "+doc.included+" opgenomen, "+
          doc.excluded+" uitgesloten. Geen toestemming of eigendomsbewijs."));
      }else if(doc.sourceSHA){
        if(mismatch(doc))article.append(create("p","tray-contradiction",
          "HOLD: de opgegeven bronmetadata spreekt de exacte Studio-bron tegen. Eerst handmatig oplossen."));
        else article.append(create("p",attachedSource(doc)?"tray-linked":"tray-missing",
          attachedSource(doc)?"Exact Studio-bronbestand aanwezig. Alleen bytevergelijking, nooit toestemming.":
          "Bijbehorende originele Studio-bytes ontbreken of wijken af."));
      }else article.append(create("p","tray-detail",
        "Dit document heeft geen enkelvoudig originele-bron-SHA. Koppel het handmatig in de bronapp."));
      const actions=create("div","tray-item-actions");
      const get=create("button","tray-retrieve","Download originele bytes");
      get.type="button";get.addEventListener("click",()=>{
        if(mismatch(doc)&&!confirm("De bronmetadata spreekt de originele Studio-inhoud tegen. Alleen voor lokale correctie downloaden?"))return;
        download(doc);
      });actions.append(get);
      const remove=create("button","tray-remove","Verwijder");
      remove.type="button";remove.addEventListener("click",()=>{
        documents.splice(documents.indexOf(doc),1);render();
        reportStatus("Document lokaal verwijderd. Gegevens zijn niet extern verzonden.");
      });actions.append(remove);
      article.append(actions);
      const caption=create("p","tray-route-text","Open de oorspronkelijke app en importeer het bestand daar zelf:");
      article.append(caption);
      const routes=create("div","tray-route-links");
      if(mismatch(doc)){
        routes.append(create("strong","tray-route-blocked","Doorgeven gepauzeerd wegens bron-tegenspraak."));
      }else if(doc.targets.length===0){
        routes.append(create("span","tray-no-import","Geen bevestigde directe import in de gebundelde apps; alleen handmatige bespreking."));
      }else for(const target of doc.targets){
        const a=create("a",null,ROUTE_NAMES[target]);a.href=ROUTE_URLS[target];
        a.target="_blank";a.rel="noopener";
        routes.append(a);
      }
      article.append(routes);
      area.append(article);
    }
    window.dispatchEvent(new CustomEvent("lightup:scope-documents", {
      detail:documents.map(d=>({
        hash:d.hash,kind:d.kind,source:d.source,source_sha:d.sourceSHA,
        risk:d.risk,missing:!!d.sourceSHA&&!attachedSource(d),conflict:mismatch(d)
      }))
    }));
  }
  async function ingest(files){
    const batch=Array.from(files||[]);
    if(!batch.length)return;
    if(documents.length+batch.length>MAX_ITEMS) {
      reportStatus("Maximum 24 documenten; verwijder eerst bestanden.",true);return;
    }
    if(batch.some(f=>f.size>MAX_DOCUMENT_BYTES) ||
      documents.reduce((n,d)=>n+d.bytes.length,0)+batch.reduce((n,f)=>n+f.size,0)>MAX_TOTAL_BYTES){
      reportStatus("Maximaal 2 MiB totaal en 256 KiB per JSON-bestand.",true);return;
    }
    const parsed=[];
    try{
      for(const file of batch){
        const doc=await parseFile(file);
        if(documents.some(d=>d.hash===doc.hash)||parsed.some(d=>d.hash===doc.hash))
          throw Error("DUPLICATE_FILE");
        parsed.push(doc);
      }
    }catch(error){
      reportStatus("HOLD — gehele nieuwe selectie ongewijzigd geweigerd. "+detailMessage(error?.message),true);
      return;
    }
    // Atomic admission: failed batch cannot partially mutate current tray.
    documents=[...documents,...parsed];
    render();
    reportStatus(parsed.length+" document(en) uitsluitend tijdelijk in dit tabblad ingeladen. Alles blijft ongeverifieerd.");
  }
  $("tray-files").addEventListener("change",async event=>{
    const files=event.target.files;
    await ingest(files);
    event.target.value="";
  });
  const zone=$("tray-drop");
  zone.addEventListener("dragover",event=>{
    if(event.dataTransfer?.types.includes("Files")){
      event.preventDefault();zone.classList.add("drag-hover");
    }
  });
  zone.addEventListener("dragleave",()=>zone.classList.remove("drag-hover"));
  zone.addEventListener("drop",event=>{
    event.preventDefault();zone.classList.remove("drag-hover");
    void ingest(event.dataTransfer?.files);
  });
  $("tray-clear").addEventListener("click",()=>{
    if(!documents.length)return;
    if(!confirm("Alle tijdelijk ingelezen bestanden uit deze browserpagina verwijderen?"))return;
    documents=[];render();reportStatus("Tijdelijke documentlade geleegd.");
  });
  $("tray-export").addEventListener("click",()=>{
    if(!documents.length)return;
    if(!confirm("Bron-SHA-256's kunnen correlatie mogelijk maken. Alleen lokaal of met bevoegde ontvangers delen?"))return;
    const packet={
      kind:"lightup.scope_workbench_local_inventory",schema_version:1,
      state:"REVIEW_ONLY_HOLD",authentication:false,consent_verified:false,
      authorized:false,grant_issued:false,dispatch_allowed:false,scan_allowed:false,
      release_allowed:false,deploy_allowed:false,
      notice:"Untrusted local document receipt. Not a proof of ownership, consent, authorization or origin.",
      files:documents.map(d=>({
        kind:d.kind,sha256:d.hash,bytes:d.bytes.length,
        original_studio_sha256:d.sourceSHA,
        original_studio_present:!!(d.source||attachedSource(d)),
        source_metadata_conflict:mismatch(d)
      }))
    };
    const uri=URL.createObjectURL(new Blob([JSON.stringify(packet,null,2)+"\n"],{type:"application/json"}));
    const anchor=create("a");anchor.href=uri;anchor.download="lightup-offline-document-inventory-HOLD.json";
    document.body.append(anchor);anchor.click();anchor.remove();
    setTimeout(()=>URL.revokeObjectURL(uri),1000);
  });
  render();
})();