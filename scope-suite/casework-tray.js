/* LightUp local-only casework source desk. CSV parsing comes from the pinned
   Remediation Casework owner module; this bridge never authenticates provenance. */
"use strict";
(() => {
  const $=id=>document.getElementById(id);
  const limit=1048576,maxCount=4,totalLimit=3145728;
  let snapshots=[];
  const summaryFields=["critical","high","medium","low","info"];
  const summaryStates=["not_tested","fix_pending","fixed","regression"];
  const parser=globalThis.LightUpCasework;
  const say=(message,error=false)=>{
    $("casework-status").textContent=message;
    $("casework-status").classList.toggle("fail",error);
  };
  const el=(tag,cls,text)=>{
    const e=document.createElement(tag);
    if(cls)e.className=cls;
    if(text!==undefined)e.textContent=text;
    return e;
  };
  const hexdigest=async(bytes)=>{
    if(!globalThis.crypto?.subtle)throw Error("SHA-256 in deze browsercontext niet beschikbaar.");
    const digest=await crypto.subtle.digest("SHA-256",bytes);
    return [...new Uint8Array(digest)].map(b=>b.toString(16).padStart(2,"0")).join("");
  };
  async function openCSV(file){
    if(!file || file.size<1||file.size>limit||!file.name.toLowerCase().endsWith(".csv"))
      throw Error("Alleen CSV tot 1 MiB is toegestaan.");
    if(!parser?.parseCSV)throw Error("Originele bronparser van Casework ontbreekt.");
    const bytes=new Uint8Array(await file.arrayBuffer());
    const text=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
    const findings=parser.parseCSV(text); // The original owner validates all five fields and source types.
    const digest=await hexdigest(bytes);
    const severities=Object.fromEntries(summaryFields.map(k=>[k,0]));
    const states=Object.fromEntries(summaryStates.map(k=>[k,0]));
    findings.forEach(f=>{severities[f.severity]++;states[f.retest_status]++;});
    return {bytes,findings,hash:digest,severities,states};
  }
  async function stage(files){
    const selected=[...files||[]];
    if(!selected.length)return;
    if(snapshots.length+selected.length>maxCount){
      say("Maximaal vier lokale CSV-bronnen tegelijk.",true);return;
    }
    if(snapshots.reduce((n,d)=>n+d.bytes.length,0)+selected.reduce((n,f)=>n+f.size,0)>totalLimit){
      say("Maximaal 3 MiB aan lokale bronnen tegelijk.",true);return;
    }
    try{
      const staged=[];
      for(const file of selected){
        const record=await openCSV(file);
        if(snapshots.some(d=>d.hash===record.hash)||staged.some(d=>d.hash===record.hash))
          throw Error("Dezelfde originele CSV-bytes zijn al opgenomen.");
        staged.push(record);
      }
      snapshots=[...snapshots,...staged];
      render();
      say(staged.length+" CSV-bron(nen) tijdelijk geopend. Herkomst en tenant zijn niet geverifieerd.");
    }catch(_){
      // No file names, raw content, IDs or adversarial importer errors in browser messages.
      say("HOLD — nieuwe selectie geheel geweigerd. Gebruik uitsluitend een geldige, geautoriseerd verkregen LightUp findings-CSV; geen bestaande bron veranderd.",true);
    }
  }
  function originalDownload(record){
    const href=URL.createObjectURL(new Blob([record.bytes],{type:"text/csv;charset=utf-8"}));
    const a=el("a");a.href=href;a.download="lightup-findings-local-"+record.hash.slice(0,12)+".csv";
    document.body.append(a);a.click();a.remove();
    setTimeout(()=>URL.revokeObjectURL(href),1000);
  }
  function summarized(record){
    return summaryFields.map(k=>k+": "+record.severities[k]).join(" · ");
  }
  function stateText(record){
    return summaryStates.map(k=>k.replaceAll("_"," ")+": "+record.states[k]).join(" · ");
  }
  function render(){
    const panel=$("casework-sources");panel.replaceChildren();
    $("casework-count").textContent=snapshots.length+" / "+maxCount;
    $("casework-empty").hidden=snapshots.length>0;
    $("casework-forget").disabled=snapshots.length===0;
    $("casework-inventory").disabled=snapshots.length===0;
    $("casework-baseline").replaceChildren();
    $("casework-candidate").replaceChildren();
    const choose=(index,text)=>{
      for(const target of ["casework-baseline","casework-candidate"]){
        const opt=el("option",null,text);opt.value=String(index);$(target).append(opt);
      }
    };
    snapshots.forEach((record,index)=>{
      const card=el("article","casework-source");
      card.append(el("h3",null,"CSV-bron "+String(index+1).padStart(2,"0")));
      card.append(el("p","tray-meta","SHA-256 "+record.hash.slice(0,22)+"… · "+record.bytes.length+" bytes"));
      card.append(el("p","casework-aggregate",
        record.findings.length+" bevindingen · "+summarized(record)));
      card.append(el("p","casework-claims","Door de bron gerapporteerde retest-staten, NIET door deze werkbank geverifieerd: "+stateText(record)));
      const buttons=el("div","tray-item-actions");
      const save=el("button","tray-retrieve","Download originele CSV");
      save.type="button";save.addEventListener("click",()=>originalDownload(record));
      buttons.append(save);
      const remove=el("button","tray-remove","Verwijder");
      remove.type="button";remove.addEventListener("click",()=>{
        snapshots=snapshots.filter(x=>x!==record);render();
        say("Originele bron uit deze tijdelijke browserwerkruimte verwijderd.");
      });
      buttons.append(remove);card.append(buttons);
      const route=el("p","tray-route-text","Open de echte offline Casework-importer en selecteer deze ongewijzigde CSV handmatig.");
      card.append(route);
      const link=el("a","tray-app-link","Open Remediation Casework →");
      link.href="apps/casework/casework/index.html";
      link.target="_blank";link.rel="noopener";
      card.append(link);
      panel.append(card);
      choose(index,"Bron "+String(index+1).padStart(2,"0")+" · "+record.hash.slice(0,12));
    });
    $("casework-compare").disabled=snapshots.length<2;
    $("casework-comparison").replaceChildren();
    $("casework-same-source").checked=false;
    if(snapshots.length>1)$("casework-candidate").value=String(snapshots.length-1);
    window.dispatchEvent(new CustomEvent("lightup:findings-sources",{
      detail:snapshots.map(d=>({
        hash:d.hash,count:d.findings.length,
        critical:d.severities.critical,high:d.severities.high,
        regression:d.states.regression,not_tested:d.states.not_tested
      }))
    }));
  }
  $("casework-files").addEventListener("change",async e=>{
    const files=e.target.files;
    await stage(files);
    e.target.value="";
  });
  $("casework-forget").addEventListener("click",()=>{
    if(!snapshots.length||!confirm("Alle tijdelijke CSV-bevindingen uit dit tabblad verwijderen?"))return;
    snapshots=[];render();say("Alle CSV-bronnen lokaal vergeten.");
  });
  $("casework-inventory").addEventListener("click",()=>{
    if(!snapshots.length)return;
    if(!confirm("SHA-256 fingerprints kunnen gevoelige bronbestanden herkenbaar maken. Alleen bedoeld voor besloten menselijke review. Inventaris downloaden?"))return;
    const manifest={
      kind:"lightup.local_remediation_receipt",schema_version:1,
      disposition:"REVIEW_ONLY_HOLD",
      authenticated:false,source_authorized:false,assessment_authorized:false,
      grant:false,consent_verified:false,scan:false,execution:false,
      retest_verified:false,release:false,
      note:"Local file SHA digests are not signatures, tenant verification, consent or remediation evidence.",
      records:snapshots.map(r=>({
        source_sha256:r.hash,bytes:r.bytes.length,count:r.findings.length,
        severity_counts:{...r.severities},reported_retest_status_counts:{...r.states}
      }))
    };
    const url=URL.createObjectURL(new Blob([JSON.stringify(manifest,null,2)+"\n"],{type:"application/json"}));
    const a=el("a");a.href=url;a.download="lightup-local-findings-receipt-HOLD.json";
    document.body.append(a);a.click();a.remove();
    setTimeout(()=>URL.revokeObjectURL(url),1000);
  });
  $("casework-compare").addEventListener("click",()=>{
    const before=snapshots[Number($("casework-baseline").value)];
    const after=snapshots[Number($("casework-candidate").value)];
    const area=$("casework-comparison");area.replaceChildren();
    if(!before||!after||before===after){
      say("Kies twee verschillende lokale exports om het verschil te bekijken.",true);return;
    }
    if(!$("casework-same-source").checked){
      say("Bevestig eerst zelf dat beide CSV's bij dezelfde echte cliënt en hetzelfde assessment horen. Deze werkbank kan dat NIET vaststellen.",true);return;
    }
    if(!confirm("Vergelijk deze twee NIET-GEATTESTEERDE exports op basis van uw eigen externe cliënt-/engagementcontrole? Dit is GEEN retestbewijs."))return;
    const diff=parser.compareSource(before.findings,after.findings);
    area.append(el("h3",null,"Voorlopige bronverschillen — GEEN retest of sluiting"));
    const text=[
      ["Ongewijzigde bevindingen",diff.unchanged.length],
      ["Nieuwe IDs in kandidaat",diff.added.length],
      ["Inhoudelijk gewijzigde IDs",diff.changed.length],
      ["Niet meer aanwezig in kandidaat",diff.missing.length]
    ];
    const grid=el("div","casework-diff");
    text.forEach(([label,n])=>{
      const tile=el("div","casework-diff-tile");tile.append(el("strong",null,String(n)),el("span",null,label));grid.append(tile);
    });
    area.append(grid);
    area.append(el("p","casework-warning","Ontbrekende bevindingen zijn niet automatisch opgelost. Gewijzigde brongegevens vereisen nieuwe menselijke beoordeling; oude planning mag niet stilzwijgend worden overgenomen. De oorspronkelijke Casework-app beoordeelt een latere verversing afzonderlijk."));
    say("Verschilweergave opgesteld uit twee lokale aangeleverde CSV's; niets teruggeschreven of geautoriseerd.");
  });
  render();
})();