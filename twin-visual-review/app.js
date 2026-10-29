"use strict";
/*
 * LightUp / Future Security / Human-only declared topology review.
 * All model entries are unverified declarations. No network, execution,
 * scanner, evidence authority, consent, credentials or persistent storage.
 */
(() => {
  const KINDS = new Set(["service", "identity", "data", "boundary"]);
  const RELATIONS = new Set(["calls", "may-access", "trusts", "crosses-boundary"]);
  const FOLLOWUPS = new Set(["needs-owner", "needs-evidence", "clarify-boundary", "lab-only-followup"]);
  const ID = /^[A-Za-z][A-Za-z0-9_-]{0,31}$/;
  const MAX_BYTES = 131072;
  const SVG = "http://www.w3.org/2000/svg";
  const el = id => document.getElementById(id);
  const status = message => { el("status").textContent = message; };
  const blankGraph = () => ({ nodes: [], edges: [] });
  let documentState = blankDocument();
  let currentMode = "current";

  function blankDocument() {
    return {
      kind: "lightup.twin_declared_review",
      version: 1,
      disposition: "HUMAN_DRAFT_HOLD",
      authority: false,
      current: blankGraph(),
      proposed: blankGraph(),
      followup: "needs-owner"
    };
  }

  function exactKeys(obj, keys) {
    return obj !== null && typeof obj === "object" && !Array.isArray(obj) &&
      Object.getPrototypeOf(obj) === Object.prototype &&
      Object.keys(obj).length === keys.length &&
      keys.every(key => Object.prototype.hasOwnProperty.call(obj, key));
  }

  function validLabel(value) {
    return typeof value === "string" && value.length >= 1 && value.length <= 80 &&
      value.trim() === value && !/[\x00-\x1f\x7f]/.test(value);
  }

  function admitGraph(graph) {
    if (!exactKeys(graph, ["nodes", "edges"]) ||
        !Array.isArray(graph.nodes) || !Array.isArray(graph.edges) ||
        graph.nodes.length > 32 || graph.edges.length > 96) {
      throw new Error("Invalid graph size or structure.");
    }
    const ids = new Set();
    for (const node of graph.nodes) {
      if (!exactKeys(node, ["id", "label", "type"]) ||
          typeof node.id !== "string" || !ID.test(node.id) ||
          !validLabel(node.label) || !KINDS.has(node.type) || ids.has(node.id)) {
        throw new Error("Invalid or duplicate declared node.");
      }
      ids.add(node.id);
    }
    const edges = new Set();
    for (const edge of graph.edges) {
      if (!exactKeys(edge, ["from", "to", "kind"]) ||
          !ids.has(edge.from) || !ids.has(edge.to) || edge.from === edge.to ||
          !RELATIONS.has(edge.kind)) {
        throw new Error("Invalid relationship or unknown endpoint.");
      }
      const key = edgeKey(edge);
      if (edges.has(key)) throw new Error("Duplicate relationship.");
      edges.add(key);
    }
    return graph;
  }

  function admitDocument(value) {
    if (!exactKeys(value, [
      "kind", "version", "disposition", "authority", "current", "proposed", "followup"
    ]) ||
      value.kind !== "lightup.twin_declared_review" ||
      value.version !== 1 || value.disposition !== "HUMAN_DRAFT_HOLD" ||
      value.authority !== false || !FOLLOWUPS.has(value.followup)) {
      throw new Error("Not an exact non-authorizing LightUp declared review v1.");
    }
    admitGraph(value.current);
    admitGraph(value.proposed);
    return value;
  }

  // A small structural JSON scanner: reject duplicate names at every nesting
  // level before JSON.parse (which otherwise silently overwrites duplicate keys).
  function parseStrictJSON(source) {
    let i = 0;
    const ws = () => { while (i < source.length && /[\x20\x09\x0a\x0d]/.test(source[i])) i++; };
    function stringValue() {
      if (source[i] !== '"') throw new Error("Expected JSON string.");
      const start = i++;
      let escaped = false;
      while (i < source.length) {
        const ch = source[i++];
        if (escaped) { escaped = false; continue; }
        if (ch === "\\") { escaped = true; continue; }
        if (ch === '"') return JSON.parse(source.slice(start, i));
        if (ch.charCodeAt(0) < 0x20) throw new Error("Invalid JSON control character.");
      }
      throw new Error("Unterminated JSON string.");
    }
    function value(depth) {
      if (depth > 12) throw new Error("JSON nesting limit exceeded.");
      ws();
      if (source[i] === "{") {
        i++; ws();
        const seen = new Set();
        if (source[i] === "}") { i++; return; }
        while (i < source.length) {
          const key = stringValue();
          if (seen.has(key)) throw new Error("Duplicate JSON key.");
          seen.add(key); ws();
          if (source[i++] !== ":") throw new Error("Invalid JSON member.");
          value(depth + 1); ws();
          if (source[i] === "}") { i++; return; }
          if (source[i++] !== ",") throw new Error("Invalid JSON object.");
          ws();
        }
        throw new Error("Unclosed JSON object.");
      }
      if (source[i] === "[") {
        i++; ws();
        if (source[i] === "]") { i++; return; }
        while (i < source.length) {
          value(depth + 1); ws();
          if (source[i] === "]") { i++; return; }
          if (source[i++] !== ",") throw new Error("Invalid JSON array.");
        }
        throw new Error("Unclosed JSON array.");
      }
      if (source[i] === '"') { stringValue(); return; }
      const tail = source.slice(i);
      const match = /^(true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(tail);
      if (!match) throw new Error("Invalid JSON value.");
      i += match[0].length;
    }
    value(0); ws();
    if (i !== source.length) throw new Error("Unexpected trailing JSON.");
    return JSON.parse(source);
  }

  function cloneGraph(graph) {
    return {
      nodes: graph.nodes.map(n => ({ id: n.id, label: n.label, type: n.type })),
      edges: graph.edges.map(e => ({ from: e.from, to: e.to, kind: e.kind }))
    };
  }

  function edgeKey(edge) { return edge.from + "|" + edge.kind + "|" + edge.to; }
  function textNode(tag, txt, cls) {
    const node = document.createElement(tag);
    node.textContent = txt;
    if (cls) node.className = cls;
    return node;
  }
  function s(tag, attrs, content) {
    const node = document.createElementNS(SVG, tag);
    for (const [key, val] of Object.entries(attrs || {})) node.setAttribute(key, String(val));
    if (content !== undefined) node.textContent = content;
    return node;
  }
  function download(name, contents, type) {
    const blob = new Blob([contents], { type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = name;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 250);
  }
  function humanEdge(edge) {
    return edge.from + " → " + edge.to + " · " + edge.kind.replaceAll("-", " ");
  }
  function differences() {
    const old = documentState.current;
    const next = documentState.proposed;
    const oldNodes = new Map(old.nodes.map(n => [n.id, n]));
    const nextNodes = new Map(next.nodes.map(n => [n.id, n]));
    const addedNodes = next.nodes.filter(n => !oldNodes.has(n.id));
    const removedNodes = old.nodes.filter(n => !nextNodes.has(n.id));
    const editedNodes = next.nodes.filter(n => oldNodes.has(n.id) &&
      (oldNodes.get(n.id).label !== n.label || oldNodes.get(n.id).type !== n.type));
    const oldEdges = new Set(old.edges.map(edgeKey));
    const nextEdges = new Set(next.edges.map(edgeKey));
    return {
      addedNodes, removedNodes, editedNodes,
      addedEdges: next.edges.filter(e => !oldEdges.has(edgeKey(e))),
      removedEdges: old.edges.filter(e => !nextEdges.has(edgeKey(e)))
    };
  }
  function metrics() {
    const d = differences();
    return [
      ["Current nodes", documentState.current.nodes.length],
      ["Proposed nodes", documentState.proposed.nodes.length],
      ["Added nodes", d.addedNodes.length],
      ["Removed nodes", d.removedNodes.length],
      ["Edited nodes", d.editedNodes.length],
      ["Added relationships", d.addedEdges.length],
      ["Removed relationships", d.removedEdges.length],
      ["Unknown validation", "ALL"]
    ];
  }

  function renderChanges() {
    const d = differences();
    const container = el("changes");
    container.replaceChildren();
    const blocks = [
      ["ADDED NODE", d.addedNodes.map(n => n.id + " · " + n.label)],
      ["REMOVED NODE", d.removedNodes.map(n => n.id + " · " + n.label)],
      ["EDITED NODE", d.editedNodes.map(n => n.id + " · " + n.label)],
      ["ADDED RELATIONSHIP", d.addedEdges.map(humanEdge)],
      ["REMOVED RELATIONSHIP", d.removedEdges.map(humanEdge)]
    ];
    let anything = false;
    for (const [label, items] of blocks) {
      for (const item of items) {
        anything = true;
        const row = textNode("div", "", "diff-row");
        row.append(textNode("span", label, "diff-tag"), textNode("span", item));
        container.appendChild(row);
      }
    }
    if (!anything) container.appendChild(textNode("p",
      "No literal differences in the declarations. Actual security state remains UNKNOWN.", "subdued"));
    el("metrics").replaceChildren(...metrics().map(([label, number]) => {
      const item = textNode("div", "", "metric");
      item.append(textNode("strong", String(number)), textNode("small", label));
      return item;
    }));
  }

  function renderList(containerId, items, makeLabel, deleteItem) {
    const container = el(containerId);
    container.replaceChildren();
    if (items.length === 0) {
      container.appendChild(textNode("p", "None declared.", "subdued"));
      return;
    }
    items.forEach((entry, index) => {
      const row = textNode("div", "", "item-row");
      row.appendChild(textNode("span", makeLabel(entry)));
      const button = textNode("button", "Remove", "danger quiet");
      button.type = "button";
      button.setAttribute("aria-label", "Remove " + makeLabel(entry));
      button.addEventListener("click", () => {
        deleteItem(entry, index);
        status("Local declaration updated. This does not affect real systems.");
        render();
      });
      row.appendChild(button);
      container.appendChild(row);
    });
  }

  function renderEditor() {
    const graph = documentState[currentMode];
    el("state").value = currentMode;
    el("followup").value = documentState.followup;
    renderList("nodes", graph.nodes, n => n.id + " · " + n.label + " [" + n.type + "]",
      n => {
        graph.nodes = graph.nodes.filter(x => x.id !== n.id);
        graph.edges = graph.edges.filter(e => e.from !== n.id && e.to !== n.id);
      });
    renderList("edges", graph.edges, humanEdge, e => {
      graph.edges = graph.edges.filter(x => edgeKey(x) !== edgeKey(e));
    });
    for (const name of ["edgeFrom", "edgeTo"]) {
      const select = el(name);
      const old = select.value;
      select.replaceChildren(...graph.nodes.map(n => {
        const option = document.createElement("option");
        option.value = n.id;
        option.textContent = n.label + " (" + n.id + ")";
        return option;
      }));
      if (graph.nodes.some(n => n.id === old)) select.value = old;
    }
  }

  function renderGraph(which) {
    const graph = documentState[which];
    const svg = el(which + "Graph");
    svg.replaceChildren();
    svg.appendChild(s("rect", { width: 600, height: 400, rx: 14, class: "backdrop" }));
    if (!graph.nodes.length) {
      svg.appendChild(s("text", { x: 300, y: 200, "text-anchor": "middle", class: "empty" },
        "No nodes declared"));
      return;
    }
    const positions = new Map();
    graph.nodes.forEach((n, index) => {
      const columns = 4;
      const col = index % columns;
      const row = Math.floor(index / columns);
      positions.set(n.id, { x: 75 + col * 150, y: 38 + row * 46 });
    });
    for (const edge of graph.edges) {
      const a = positions.get(edge.from);
      const b = positions.get(edge.to);
      const line = s("line", { x1: a.x, y1: a.y + 8, x2: b.x, y2: b.y + 8, class: "connection" });
      line.appendChild(s("title", {}, humanEdge(edge) + " (unverified)"));
      svg.appendChild(line);
    }
    for (const node of graph.nodes) {
      const p = positions.get(node.id);
      const group = s("g", { class: "graph-node " + node.type });
      group.append(
        s("rect", { x: p.x - 66, y: p.y - 13, width: 132, height: 27, rx: 6 }),
        s("text", { x: p.x, y: p.y + 5, "text-anchor": "middle" },
          node.label.length > 19 ? node.label.slice(0, 17) + "…" : node.label),
        s("title", {}, node.id + " · " + node.label + " · " + node.type + " (declared)")
      );
      svg.appendChild(group);
    }
  }

  // Bounded declarative *connection chains*, never verified attack paths.
  function declaredChains(graph) {
    const byId = new Map(graph.nodes.map(n => [n.id, n]));
    const adjacency = new Map(graph.nodes.map(n => [n.id, []]));
    for (const edge of graph.edges) adjacency.get(edge.from).push(edge);
    for (const edges of adjacency.values()) edges.sort((a, b) => edgeKey(a).localeCompare(edgeKey(b)));
    const roots = graph.nodes.filter(n => n.type === "identity")
      .sort((a, b) => a.id.localeCompare(b.id));
    const results = [];
    let visits = 0;
    let limited = false;
    function walk(id, members, steps) {
      if (limited) return;
      if (++visits > 5000) { limited = true; return; }
      const node = byId.get(id);
      if (node.type === "data" && steps.length) {
        results.push({
          key: steps.map(edgeKey).join(" / "),
          text: members.map(name => byId.get(name).label + " (" + name + ")").join(" → ")
        });
        if (results.length >= 200) limited = true;
        return;
      }
      if (steps.length >= 4) return;
      for (const edge of adjacency.get(id)) {
        if (members.includes(edge.to)) continue;
        walk(edge.to, [...members, edge.to], [...steps, edge]);
        if (limited) return;
      }
    }
    for (const root of roots) {
      walk(root.id, [root.id], []);
      if (limited) break;
    }
    return { entries: results, limited };
  }

  function renderChains() {
    const old = declaredChains(documentState.current);
    const future = declaredChains(documentState.proposed);
    const oldByKey = new Map(old.entries.map(p => [p.key, p]));
    const futureByKey = new Map(future.entries.map(p => [p.key, p]));
    const added = future.entries.filter(p => !oldByKey.has(p.key));
    const missing = old.entries.filter(p => !futureByKey.has(p.key));
    const cells = [
      ["Current declarations", old.entries.length],
      ["Future declarations", future.entries.length],
      ["Future-only", added.length],
      ["Current-only", missing.length]
    ];
    el("chainMetrics").replaceChildren(...cells.map(([label, value]) => {
      const item = textNode("div", "", "metric");
      item.append(textNode("strong", String(value)), textNode("small", label));
      return item;
    }));
    const hasLimit = old.limited || future.limited;
    el("chainNotice").textContent = hasLimit
      ? "HOLD: bounded enumeration limit reached; displayed list and comparison are incomplete. No completeness claim."
      : "All displayed chains are human-authored hypotheses, not technical reachability or security evidence.";
    const host = el("chainList");
    host.replaceChildren();
    for (const [caption, entries] of [
      ["FUTURE-ONLY DECLARATION", added],
      ["CURRENT-ONLY DECLARATION", missing]
    ]) {
      for (const path of entries) {
        const row = textNode("div", "", "diff-row");
        row.append(textNode("span", caption, "diff-tag"), textNode("span", path.text));
        host.appendChild(row);
      }
    }
    if (!added.length && !missing.length) {
      host.appendChild(textNode("p",
        "No difference in the bounded declared identity-to-data chains. Actual security outcome UNKNOWN.",
        "subdued"));
    }
  }

  function render() {
    admitDocument(documentState);
    renderEditor();
    renderChanges();
    renderChains();
    renderGraph("current");
    renderGraph("proposed");
  }

  function loadExample() {
    if (!window.confirm("Replace your entire unsaved draft with fictional example data?")) return;
    const nodes = [
      { id: "visitor", label: "Fictional visitor", type: "identity" },
      { id: "gateway", label: "Fictional API", type: "service" },
      { id: "records", label: "Fictional records", type: "data" },
      { id: "tenant_edge", label: "Tenant boundary", type: "boundary" }
    ];
    documentState = blankDocument();
    documentState.current = {
      nodes: nodes.map(n => ({ ...n })),
      edges: [
        { from: "visitor", to: "gateway", kind: "calls" },
        { from: "gateway", to: "tenant_edge", kind: "crosses-boundary" }
      ]
    };
    documentState.proposed = {
      nodes: [...nodes.map(n => ({ ...n })), { id: "export", label: "Fictional export", type: "service" }],
      edges: [
        ...documentState.current.edges.map(e => ({ ...e })),
        { from: "gateway", to: "export", kind: "calls" },
        { from: "export", to: "records", kind: "may-access" }
      ]
    };
    status("Fictional declarations loaded; none represents a real security finding.");
    render();
  }

  el("demo").addEventListener("click", loadExample);
  el("reset").addEventListener("click", () => {
    if (!window.confirm("Discard all current and proposed declarations, without recovery?")) return;
    documentState = blankDocument();
    status("All local declarations cleared.");
    render();
  });
  el("copy").addEventListener("click", () => {
    if (!window.confirm("Replace the proposed future draft with a copy of current?")) return;
    documentState.proposed = cloneGraph(documentState.current);
    status("Proposed draft replaced locally; no real topology changed.");
    render();
  });
  el("state").addEventListener("change", e => {
    currentMode = e.target.value === "proposed" ? "proposed" : "current";
    render();
  });
  el("followup").addEventListener("change", e => {
    if (FOLLOWUPS.has(e.target.value)) {
      documentState.followup = e.target.value;
      status("Human-only question routing updated.");
    }
  });
  el("nodeForm").addEventListener("submit", e => {
    e.preventDefault();
    const id = el("nodeId").value;
    const label = el("nodeLabel").value;
    const type = el("nodeType").value;
    const graph = documentState[currentMode];
    if (!ID.test(id) || !validLabel(label) || !KINDS.has(type) ||
        graph.nodes.length >= 32 || graph.nodes.some(n => n.id === id)) {
      status("HOLD: invalid ID, label, duplicate, or 32-node limit.");
      return;
    }
    graph.nodes.push({ id, label, type });
    el("nodeForm").reset();
    status("Added unverified node to " + currentMode + " declaration.");
    render();
  });
  el("edgeForm").addEventListener("submit", e => {
    e.preventDefault();
    const from = el("edgeFrom").value;
    const to = el("edgeTo").value;
    const kind = el("edgeKind").value;
    const graph = documentState[currentMode];
    const edge = { from, to, kind };
    if (!graph.nodes.some(n => n.id === from) || !graph.nodes.some(n => n.id === to) ||
        from === to || !RELATIONS.has(kind) || graph.edges.length >= 96 ||
        graph.edges.some(x => edgeKey(x) === edgeKey(edge))) {
      status("HOLD: invalid/duplicate relationship or 96-relationship limit.");
      return;
    }
    graph.edges.push(edge);
    status("Added unverified " + kind + " declaration.");
    render();
  });
  el("save").addEventListener("click", () => {
    try {
      admitDocument(documentState);
      download("lightup-PRIVATE-twin-declaration.json", JSON.stringify(documentState, null, 2) + "\n",
        "application/json");
      status("PRIVATE self-declared JSON saved locally. It is not encrypted or authoritative.");
    } catch (_) { status("HOLD: cannot export invalid local declaration."); }
  });
  el("counts").addEventListener("click", () => {
    const d = differences();
    const counts = {
      kind: "lightup.twin_aggregate_counts",
      version: 1,
      disposition: "HUMAN_DRAFT_HOLD",
      authority: false,
      current_nodes: documentState.current.nodes.length,
      current_relationships: documentState.current.edges.length,
      proposed_nodes: documentState.proposed.nodes.length,
      proposed_relationships: documentState.proposed.edges.length,
      added_nodes: d.addedNodes.length,
      removed_nodes: d.removedNodes.length,
      edited_nodes: d.editedNodes.length,
      added_relationships: d.addedEdges.length,
      removed_relationships: d.removedEdges.length,
      validation: "UNKNOWN"
    };
    download("lightup-anonymous-declared-counts.json", JSON.stringify(counts, null, 2) + "\n",
      "application/json");
    status("Only untrusted aggregate counts exported. This is not a permission or risk verdict.");
  });
  el("countsCsv").addEventListener("click", () => {
    const d = differences();
    const lines = [
      ["metric", "declared_count"],
      ["current_nodes", documentState.current.nodes.length],
      ["current_relationships", documentState.current.edges.length],
      ["proposed_nodes", documentState.proposed.nodes.length],
      ["proposed_relationships", documentState.proposed.edges.length],
      ["added_nodes", d.addedNodes.length],
      ["removed_nodes", d.removedNodes.length],
      ["edited_nodes", d.editedNodes.length],
      ["added_relationships", d.addedEdges.length],
      ["removed_relationships", d.removedEdges.length]
    ].map(row => row.join(",")).join("\r\n") + "\r\n";
    download("lightup-anonymous-declared-counts.csv", lines, "text/csv;charset=utf-8");
    status("Source-free unverified numeric CSV exported. No identity, permission or verdict.");
  });
  el("brief").addEventListener("click", () => {
    const d = differences();
    const section = (heading, values) =>
      "\n" + heading + " (" + values.length + ")\n" +
      (values.length ? values.map(v => "- " + v).join("\n") : "- None declared") + "\n";
    const content = [
      "LIGHTUP · PRIVATE HUMAN-ONLY FUTURE STATE DECLARATION",
      "HOLD: not authenticated, assessed, observed, verified or authorized.",
      "No changed/missing graph edge proves a security improvement, vulnerability or remediation.",
      "No scanner, model, tenant lookup, consent, grant, network or target was used.",
      "Owner question: " + documentState.followup,
      section("Added nodes", d.addedNodes.map(n => n.id + " [" + n.type + "] " + n.label)),
      section("Removed nodes", d.removedNodes.map(n => n.id + " [" + n.type + "] " + n.label)),
      section("Edited nodes", d.editedNodes.map(n => n.id + " [" + n.type + "] " + n.label)),
      section("Added declared relationships", d.addedEdges.map(humanEdge)),
      section("Removed declared relationships", d.removedEdges.map(humanEdge)),
      "PRIVATE: self-declared component names may be sensitive; saved text is not encrypted.",
      "DRAFT/HOLD: all original security, source-owner, CI, authorization and HUMAN GO gates remain.",
      ""
    ].join("\n");
    download("lightup-PRIVATE-human-change-review.txt", content, "text/plain;charset=utf-8");
    status("PRIVATE human-only brief saved. It contains component labels; treat as sensitive.");
  });
  el("import").addEventListener("change", async e => {
    const file = e.target.files && e.target.files[0];
    e.target.value = "";
    if (!file) return;
    if (file.size > MAX_BYTES || file.size < 2) {
      status("HOLD: private file exceeds 128 KiB or is empty; current work preserved.");
      return;
    }
    try {
      const bytes = await file.arrayBuffer();
      if (bytes.byteLength > MAX_BYTES) throw new Error("Oversized input.");
      const source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      const loaded = admitDocument(parseStrictJSON(source));
      if (!window.confirm("Replace both declarations and local HUMAN follow-up with this UNTRUSTED PRIVATE import?")) {
        status("Import cancelled; current work preserved.");
        return;
      }
      documentState = loaded;
      status("PRIVATE untrusted declaration resumed in memory. No source identity or authority verified.");
      render();
    } catch (_) {
      status("HOLD: malformed, ambiguous, noncanonical or unauthorized-looking input; current work preserved.");
    }
  });
  render();
  status("Empty private declared workspace. No local data has been persisted.");
})();