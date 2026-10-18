/* LightUp authenticated offline export: local operator ACTION PLANNING only.
 * Not permission, immutable consent, live revocation or authorization. */
(() => {
  'use strict';
  const raw = 'LIGHTUP_SNAPSHOT_B64_PLACEHOLDER';
  const snapshot = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(raw), c => c.charCodeAt(0))));
  if (snapshot.format !== 'lightup.authorization_casework_snapshot_v1' ||
      snapshot.disposition !== 'REVIEW_ONLY') return;
  const FALSE = Object.freeze({
    client_consent_verified:false, operator_consent_verified:false,
    authorization_granted:false, execution_allowed:false, release_approved:false
  });
  const statuses = Object.freeze(['open', 'working', 'escalated', 'locally_documented']);
  const severity = Object.freeze({
    TENANT_LINEAGE_MISMATCH: 5,
    UNTRUSTED_APPROVED_REQUEST_ORIGIN: 5,
    INVALID_GRANT_ASSETS: 5,
    INVALID_GRANT_WINDOW: 5,
    INVALID_GRANT_CREATION_TIME: 5,
    NO_COMPATIBLE_APPROVED_REQUEST: 4,
    AMBIGUOUS_APPROVED_REQUEST_MATCH: 4,
    UNBOUND_APPROVAL_REQUEST: 4,
    EXPIRED_GRANT_WINDOW: 3,
    NO_GRANT_RECORD: 2
  });
  const $ = id => document.getElementById(id);
  const cases = [];
  snapshot.engagements.forEach((e, ei) => {
    const grants = e.grant_findings.length ? e.grant_findings : [{
      grant_number:null, window:'none', flags:['NO_GRANT_RECORD'],
      next_action:'Record not found. No authority or active work implied.'
    }];
    grants.forEach((grant, gi) => {
      const id = String(ei) + '-' + String(gi);
      const score = Math.max(0, ...grant.flags.map(f => severity[f] || 2));
      cases.push(Object.freeze({
        id, client:e.client, engagement:e.engagement, engagement_status:e.engagement_status,
        requests:e.requests, approved:e.approved_requests, untrusted:e.untrusted_approved_requests,
        grant:grant.grant_number || '-', window:grant.window, flags:Object.freeze([...grant.flags]),
        action:grant.next_action, score
      }));
    });
  });
  Object.freeze(cases);
  const casesById = new Map(cases.map(c => [c.id, c]));
  let plans = Object.create(null), selected = cases.length ? cases[0].id : null;
  let modified = false;
  const control = id => $(id);
  const text = (tag, value, cls) => {
    const node = document.createElement(tag);
    node.textContent = String(value == null ? '' : value);
    if (cls) node.className = cls;
    return node;
  };
  const empty = () => ({status:'open', owner:'', ticket:'', due:'', notes:'', resolution:''});
  const read = id => plans[id] || empty();
  const inform = value => { control('workspaceFeedback').textContent = value; };
  const mark = () => {
    modified = true;
    control('workspaceUnsaved').textContent = 'Local changes not exported';
  };
  const valid = p => {
    if (!p || typeof p !== 'object' || Array.isArray(p)) return false;
    if (Object.keys(p).sort().join(',') !== 'due,notes,owner,resolution,status,ticket') return false;
    if (!statuses.includes(p.status)) return false;
    for (const [key, limit] of [['owner',90],['ticket',120],['notes',2000],['resolution',1200]]) {
      if (typeof p[key] !== 'string' || p[key].length > limit ||
          /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(p[key])) return false;
    }
    if (typeof p.due !== 'string' || (p.due && !/^\d{4}-\d{2}-\d{2}$/.test(p.due))) return false;
    if (p.due && Number.isNaN(Date.parse(p.due + 'T00:00:00Z'))) return false;
    return true;
  };
  const count = () => {
    const set = cases.filter(c => read(c.id).status !== 'locally_documented');
    const now = new Date();
    const today = [String(now.getFullYear()).padStart(4,'0'),
      String(now.getMonth()+1).padStart(2,'0'),
      String(now.getDate()).padStart(2,'0')].join('-');
    const overdue = set.filter(c => read(c.id).due && read(c.id).due < today).length;
    control('workspaceTotals').textContent = cases.length + ' local cases · ' +
      set.length + ' need follow-up · ' +
      cases.filter(c => read(c.id).status === 'escalated').length + ' escalated · ' +
      overdue + ' overdue action dates';
  };
  const matches = c => {
    const needle = control('workspaceSearch').value.toLocaleLowerCase();
    const state = control('workspaceState').value;
    const critical = control('workspaceCritical').checked;
    const line = [c.client,c.engagement,c.flags.join(' '),c.action,read(c.id).owner,read(c.id).ticket].join(' ').toLocaleLowerCase();
    return (!needle || line.includes(needle)) &&
      (state === 'all' || read(c.id).status === state) && (!critical || c.score >= 5);
  };
  const sorted = () => cases.filter(matches).sort((a,b) =>
    (read(a.id).status === 'locally_documented') - (read(b.id).status === 'locally_documented') ||
    b.score-a.score || a.client.localeCompare(b.client) ||
    a.engagement.localeCompare(b.engagement));
  const renderList = () => {
    const list = control('workspaceCases');
    list.replaceChildren();
    for (const c of sorted()) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'caseChoice' + (c.id === selected ? ' selected' : '');
      button.setAttribute('aria-pressed', c.id === selected ? 'true':'false');
      button.append(text('strong',c.client+' / '+c.engagement));
      button.append(text('span',' · Severity '+c.score+' · '+read(c.id).status,'muted'));
      button.append(text('small',c.flags.join(' · '),'muted'));
      button.addEventListener('click', () => {saveEditor(); selected=c.id; render();});
      list.append(button);
    }
    if (!list.children.length) list.append(text('p','No cases match this filter.','muted'));
    count();
  };
  const setValue = (id,value) => {control(id).value = value;};
  const renderEditor = () => {
    const c = casesById.get(selected);
    const editor = control('workspaceEditor');
    editor.hidden = !c;
    if (!c) {control('workspaceTitle').textContent = 'No case selected';return;}
    const p = read(c.id);
    control('workspaceTitle').textContent = c.client + ' / ' + c.engagement + ' — record ' + c.grant;
    control('workspaceFlags').replaceChildren();
    for (const flag of c.flags) control('workspaceFlags').append(text('span',flag,'flag'));
    control('workspaceNotice').textContent = c.action +
      ' · Original window label: '+c.window+'. Source review is not a verified authorization or retest.';
    for (const [id,key] of [['workspaceOwner','owner'],['workspaceTicket','ticket'],
                             ['workspaceDue','due'],['workspaceNotes','notes'],
                             ['workspaceResolution','resolution'],['workspaceStatus','status']])
      setValue(id, p[key]);
  };
  const render = () => {renderList(); renderEditor();};
  const saveEditor = () => {
    const c = casesById.get(selected);
    if (!c) return;
    const p = {
      owner:control('workspaceOwner').value,
      ticket:control('workspaceTicket').value,
      due:control('workspaceDue').value,
      notes:control('workspaceNotes').value,
      resolution:control('workspaceResolution').value,
      status:control('workspaceStatus').value
    };
    if (!valid(p)) {inform('Case data exceeds limits or contains invalid fields; changes not saved.');return;}
    if (JSON.stringify(p)!==JSON.stringify(read(c.id))) {plans[c.id]=p;mark();}
    renderList();
  };
  const safeCsv = value => {
    let v=String(value==null?'':value).replace(/[\u0000-\u001f\u007f]/g,' ').trim();
    if (/^[=+\-@]/.test(v)) v="'"+v;
    return '"'+v.replace(/"/g,'""')+'"';
  };
  const downloadable = (name,mime,payload) => {
    if (new Blob([payload]).size > 512000) {inform('Export exceeds 500 KiB limit. Reduce notes or case scope.');return;}
    const blob = new Blob([payload],{type:mime});
    const url = URL.createObjectURL(blob);
    const link=document.createElement('a');
    link.href=url;link.download=name;document.body.append(link);link.click();link.remove();
    setTimeout(()=>URL.revokeObjectURL(url),30000);
    modified=false;
    control('workspaceUnsaved').textContent = 'Local action plan exported';
    inform('Saved locally. Export is REVIEW_ONLY, unsigned, sensitive and never grants authority.');
  };
  const bulkUpdate = mode => {
    saveEditor();
    const filtered = sorted().filter(c => read(c.id).status !== 'locally_documented');
    const eligible = filtered.filter(c =>
      mode === 'assign' ? !read(c.id).owner : read(c.id).status !== 'escalated');
    const owner = control('workspaceBulkOwner').value.trim();
    if (mode === 'assign' && (!owner || owner.length > 90 ||
        /[\u0000-\u001f]/.test(owner))) {
      inform('Enter a bounded responsible person/team before assigning cases.');
      return;
    }
    if (!eligible.length) {inform('No eligible unresolved cases in the current filters.');return;}
    const label = mode === 'assign' ? 'assign' : 'escalate';
    if (!window.confirm('Locally '+label+' '+eligible.length+' filtered issues? This will not change the LightUp database or authorize anything.'))return;
    for (const c of eligible) {
      const p={...read(c.id)};
      if (mode === 'assign') p.owner=owner;
      else p.status='escalated';
      if (!valid(p)) {inform('HOLD: encountered invalid local data.');return;}
      plans[c.id]=p;
    }
    mark();
    render();
    inform(eligible.length+' local follow-up cases updated. Export a private action plan to retain changes; authorization remains unverified.');
  };
  const exportPlan = () => {
    saveEditor();
    const payload = {
      format:'lightup.authorization_casework_actions_v1',
      disposition:'REVIEW_ONLY', authority:{...FALSE},
      source_fingerprint:snapshot.fingerprint,
      cases:cases.map(c => ({id:c.id, ...read(c.id)}))
    };
    downloadable('lightup-authorization-actions.json','application/json;charset=utf-8',
      JSON.stringify(payload,null,2)+'\n');
  };
  const exportCsv = () => {
    saveEditor();
    const rows=[['disposition','client','engagement','grant_number','severity',
                 'review_flags','operator_status','assigned_owner','reference_ticket',
                 'due_date','action_summary','operator_notes','local_resolution']];
    for (const c of sorted()) {
      const p=read(c.id);
      rows.push(['REVIEW_ONLY',c.client,c.engagement,c.grant,c.score,c.flags.join(';'),
                 p.status,p.owner,p.ticket,p.due,c.action,p.notes,p.resolution]);
    }
    downloadable('lightup-authorization-actions.csv','text/csv;charset=utf-8',
      rows.map(row=>row.map(safeCsv).join(',')).join('\r\n')+'\r\n');
  };
  const importPlan = async input => {
    if (!input || input.size > 512000) throw Error('Import must be a local JSON file smaller than 500 KiB.');
    const parsed=JSON.parse(await input.text());
    if (!parsed || parsed.format !== 'lightup.authorization_casework_actions_v1' ||
        parsed.disposition !== 'REVIEW_ONLY' ||
        parsed.source_fingerprint !== snapshot.fingerprint ||
        JSON.stringify(parsed.authority) !== JSON.stringify(FALSE) ||
        !Array.isArray(parsed.cases) || parsed.cases.length !== cases.length)
      throw Error('Import does not match the exact review snapshot or has invalid authority flags.');
    const next=Object.create(null), seen=new Set();
    for (const row of parsed.cases) {
      if (!row || typeof row !== 'object' || Array.isArray(row) ||
          Object.keys(row).sort().join(',') !== 'due,id,notes,owner,resolution,status,ticket' ||
          typeof row.id !== 'string' || !casesById.has(row.id) || seen.has(row.id))
        throw Error('Case IDs or schema do not match this review snapshot.');
      const {id,...p}=row;
      if (!valid(p)) throw Error('Invalid or oversized operator action.');
      next[id]=p;seen.add(id);
    }
    // Full atomic swap, never partially apply an invalid file.
    plans=next;selected=cases.length ? cases[0].id:null;
    modified=true;
    control('workspaceUnsaved').textContent='Imported action plan needs export to persist';
    render();
    inform('Imported exact-snapshot action plan. Local status NEVER verifies a grant or consent.');
  };
  for (const id of ['workspaceOwner','workspaceTicket','workspaceDue','workspaceNotes',
                     'workspaceResolution','workspaceStatus'])
    control(id).addEventListener('change', saveEditor);
  for (const id of ['workspaceSearch','workspaceState','workspaceCritical'])
    control(id).addEventListener('input',renderList);
  control('workspaceBulkAssign').addEventListener('click',()=>bulkUpdate('assign'));
  control('workspaceBulkEscalate').addEventListener('click',()=>bulkUpdate('escalate'));
  control('workspaceExport').addEventListener('click',exportPlan);
  control('workspaceCsv').addEventListener('click',exportCsv);
  control('workspaceImport').addEventListener('change',async event=>{
    const file=event.target.files[0];
    if(!file)return;
    try {await importPlan(file);}
    catch(error){inform('HOLD: '+(error instanceof Error?error.message:'Invalid import')); }
    finally {event.target.value='';}
  });
  window.addEventListener('beforeunload',event=>{
    if(modified){event.preventDefault();event.returnValue='';}
  });
  render();
})();
