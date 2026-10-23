"use strict";
(() => {
  const data = JSON.parse(document.getElementById("lightupSource").textContent);
  const roles = ["unassigned", "source_owner", "reviewer", "privacy", "operator"];
  const bucketRank = {"PAST_PLANNED_DATE": 0, "PLANNED_FOR_REFERENCE_DAY": 1,
                      "FUTURE_PLANNED_DATE": 2, "UNSCHEDULED": 3};
  const stageRank = {"PENDING_ORIGINAL": 0, "NEEDS_ORIGINAL_EVIDENCE": 1,
                     "NEEDS_SOURCE_OWNER": 2, "NEEDS_PRIVACY_REVIEW": 3,
                     "AWAITING_INPUT": 4, "HUMAN_DISCUSSION": 5};
  const cap = Object.fromEntries(roles.map(r => [r, 0]));
  const capInputs = {};
  const $ = id => document.getElementById(id);
  const make = (tag, value, parent) => {
    const el = document.createElement(tag);
    if (value !== null && value !== undefined) el.textContent = String(value);
    if (parent) parent.appendChild(el);
    return el;
  };
  const datePlus = (days) => {
    const d = new Date(data.reference_date + "T00:00:00Z");
    d.setUTCDate(d.getUTCDate() + days);
    return d.toISOString().slice(0, 10);
  };
  const rows = data.sources.flatMap(source => source.rows.map(row => ({
    ...row, agenda: source.slot, sourceStatus: source.claimed_status
  })));
  const rowOrder = (a, b) => (
    bucketRank[a.date_bucket] - bucketRank[b.date_bucket] ||
    (a.review_date || "9999").localeCompare(b.review_date || "9999") ||
    stageRank[a.stage] - stageRank[b.stage] ||
    a.agenda - b.agenda || a.source_slot - b.source_slot
  );
  const roleFilter = $("roleFilter");
  for (const role of roles) {
    const opt = make("option", role, roleFilter);
    opt.value = role;
    const label = make("label", null, $("capacityControls"));
    make("span", role + " · hypothetical weekly actions", label);
    const input = make("input", null, label);
    input.type = "number";
    input.min = "0"; input.max = "100"; input.step = "1";
    input.value = "0";
    capInputs[role] = input;
    input.setAttribute("aria-label", role + " weekly human touchpoints");
    input.addEventListener("input", () => {
      const val = Number(input.value);
      if (!Number.isInteger(val) || val < 0 || val > 100) {
        input.setCustomValidity("Use a whole number from 0 to 100");
      } else {
        input.setCustomValidity("");
        cap[role] = val;
      }
      paint();
    });
  }
  $("reference").value = data.reference_date;
  $("sourceCount").textContent = data.sources.length;
  $("allCount").textContent = rows.length;
  $("weeks").addEventListener("input", paint);
  roleFilter.addEventListener("change", paint);

  let safeAggregate = null;
  function paint() {
    const weeks = Number($("weeks").value);
    if (!Number.isInteger(weeks) || weeks < 1 || weeks > 12) {
      $("weeks").setCustomValidity("Use 1–12 planning weeks");
      $("export").disabled = true;
      return;
    }
    $("weeks").setCustomValidity("");
    $("export").disabled = false;
    const planned = [];
    const workload = [];
    for (const role of roles) {
      const pool = rows.filter(x => x.next_role === role).sort(rowOrder);
      const limit = cap[role] * weeks;
      pool.forEach((row, index) => {
        const assigned = cap[role] > 0 && index < limit;
        const week = assigned ? Math.floor(index / cap[role]) + 1 : null;
        planned.push({ ...row, week });
      });
      workload.push({role, actions: pool.length, capacity: cap[role],
                     slotted: Math.min(pool.length, limit),
                     outstanding: Math.max(0, pool.length - limit)});
    }
    const placed = workload.reduce((sum, x) => sum + x.slotted, 0);
    $("plannedCount").textContent = placed;
    $("openCount").textContent = rows.length - placed;
    const roleRows = $("roleRows"); roleRows.replaceChildren();
    for (const r of workload) {
      const tr = make("tr", null, roleRows);
      for (const val of [r.role, r.actions, r.capacity, r.slotted, r.outstanding]) {
        make("td", val, tr);
      }
    }
    const queue = $("queueRows"); queue.replaceChildren();
    planned.sort((a, b) => (
      Number(a.week === null) - Number(b.week === null) ||
      (a.week || 999) - (b.week || 999) ||
      rowOrder(a, b)
    ));
    for (const item of planned) {
      if (roleFilter.value !== "all" && roleFilter.value !== item.next_role) continue;
      const tr = make("tr", null, queue);
      const proposed = item.week === null ? "NO HYPOTHETICAL SLOT" :
        "Week " + item.week + " / " + datePlus((item.week - 1) * 7);
      for (const value of [item.agenda, item.source_slot, item.next_role, item.stage,
                           item.review_date || "—", item.date_bucket, proposed,
                           item.sourceStatus]) make("td", value, tr);
    }
    safeAggregate = {
      schema: "lightup.assessment_portfolio_capacity_aggregate.v1",
      reference_date: data.reference_date,
      claimed_status: data.claimed_status,
      source_agenda_count: data.sources.length,
      original_human_actions: rows.length,
      hypothetical_weeks: weeks,
      original_role_workload: Object.fromEntries(workload.map(r => [
        r.role, {actions:r.actions, hypothetical_weekly_capacity:r.capacity,
                 slotted:r.slotted, without_slot:r.outstanding}
      ])),
      authorized: false, consent_verified: false, dispatch_allowed: false,
      release_allowed: false
    };
  }
  $("export").addEventListener("click", () => {
    if (!safeAggregate) return;
    const blob = new Blob([JSON.stringify(safeAggregate, null, 2) + "\n"],
                          {type: "application/json"});
    const url = URL.createObjectURL(blob);
    const a = make("a", null, document.body);
    a.href = url; a.download = "lightup-human-capacity-aggregate.json";
    a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  });
  globalThis.LightUpHumanPlanAPI = {
    view: () => ({weeks:Number($("weeks").value),capacities:{...cap}}),
    restore: (weeks,capacities) => {
      for (const role of roles) {cap[role]=capacities[role];capInputs[role].value=String(cap[role]);capInputs[role].setCustomValidity("");}
      $("weeks").value=String(weeks);paint();
    }
  };
  paint();
})();
