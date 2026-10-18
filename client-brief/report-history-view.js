/* Private reviewed timeline presenter. All client handoffs strip historical source hashes. */
(function(global){
'use strict';
const html=v=>String(v??'').replace(/[&<>"']/g,k=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[k]));
function redact(t){
 if(!t||t.kind!=='lightup.client_brief_aggregate_history')throw Error('Invalid private report history.');
 return Object.freeze({kind:'lightup.client_brief_redacted_history',disposition:'REVIEW_ONLY_DRAFT_HOLD',
  source_count:t.source_history_count,chronological_order_authenticated:false,
  same_client_automatically_verified:false,permission_inferred:false,verified_remediation:false,
  entries:t.entries.map(x=>Object.freeze({order:x.order,current:x.is_current,
   findings:x.findings,critical_high:x.critical_high,source_regressions:x.retest.regression,
   source_reported_fixed:x.retest.fixed,proposed_scope_risk:x.proposed_scope?.risk??null,
   count_change:x.delta.risk_change,urgent_change:x.delta.urgent_change,
   regression_change:x.delta.regressions_change,proposed_scope_risk_change:x.delta.scope_risk_change,
   proposed_scope_revision_changed:x.delta.scope_identity_changed})),
  warning:'Reviewer-declared source order and client context; counts are source-reported, not verified improvement, remediation, chronology or scope authorization.'});
}
function display(data){
 if(!data)return '<p>No earlier original aggregate briefing attached. Current data alone cannot prove a trend.</p>';
 const peakUrgent=Math.max(1,...data.entries.map(x=>x.critical_high));
 const peakRegression=Math.max(1,...data.entries.map(x=>x.source_regressions));
 const chart='<div class="history-chart" role="group" aria-label="Reported critical or high findings and source regressions by unverified review order">'+data.entries.map(x=>
  '<div class="history-bar"><strong>Snapshot '+x.order+(x.current?' (current)':' (prior)')+'</strong><label>Reported critical/high: '+x.critical_high+'<progress max="'+peakUrgent+'" value="'+x.critical_high+'"></progress></label><label>Source regressions: '+x.source_regressions+'<progress max="'+peakRegression+'" value="'+x.source_regressions+'"></progress></label></div>').join('')+'</div>';
 const body=data.entries.map(x=>'<tr><td>'+x.order+(x.current?' · current':' · prior')+'</td><td>'+x.findings+'</td><td>'+x.critical_high+'</td><td>'+x.source_regressions+'</td><td>'+x.source_reported_fixed+'</td><td>'+(x.urgent_change===null?'—':(x.urgent_change>0?'+':'')+x.urgent_change)+'</td><td>'+(x.proposed_scope_risk??'—')+'</td><td>'+(x.proposed_scope_revision_changed===null?'unknown':x.proposed_scope_revision_changed?'changed':'same')+'</td></tr>').join('');
 return '<p>'+html(data.source_count)+' unsigned briefing snapshots in reviewer-declared order. <strong>Neither chronology nor client identity is authenticated</strong>. Less critical/high or more source-reported fixed findings does not prove successful remediation.</p>' + chart + '<div class="history-table-scroll"><table><thead><tr><th>Declared order</th><th>Findings</th><th>Critical/high</th><th>Regressions</th><th>Source fixed</th><th>Δ Critical/high</th><th>Proposed risk</th><th>Proposed scope revision</th></tr></thead><tbody>'+body+'</tbody></table></div>';
}
global.LightUpBriefHistoryView=Object.freeze({redact,display});
})(window);
