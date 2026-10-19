"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const KEY = "evoting_admin_token";
  const ROLE_TABS = {
    ADMIN: ["overview", "elections", "voters", "officers", "results", "audit"],
    REGISTRAR: ["overview", "voters"],
    AUDITOR: ["overview", "results", "audit"],
  };
  const state = {
    token: sessionStorage.getItem(KEY) || "",
    role: "",
    username: "",
    parties: [],
    elections: [],
  };

  /* ---------- helpers ---------- */
  function explain(data) {
    if (!data || !data.detail) return "Request failed.";
    if (typeof data.detail === "string") return data.detail;
    if (Array.isArray(data.detail)) return data.detail.map((e) => e.msg || "").join(", ");
    return "Request failed.";
  }

  async function api(path, options) {
    const opts = options || {};
    const headers = {};
    let body;
    if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(opts.body);
    }
    if (state.token) headers.Authorization = "Bearer " + state.token;
    const response = await fetch(path, { method: opts.method || "GET", headers, body });
    let data = null;
    try { data = await response.json(); } catch (_) { /* empty body */ }
    if (!response.ok) {
      if (response.status === 401 && state.token) {
        forceLogout("Session expired. Sign in again.");
      }
      const error = new Error(explain(data));
      error.status = response.status;
      throw error;
    }
    return data;
  }

  async function download(path, filename) {
    const headers = {};
    if (state.token) headers.Authorization = "Bearer " + state.token;
    const response = await fetch(path, { headers });
    if (!response.ok) {
      if (response.status === 401 && state.token) forceLogout("Session expired. Sign in again.");
      let data = null;
      try { data = await response.json(); } catch (_) { /* no body */ }
      throw new Error(explain(data));
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  const fmt = (n) => Number(n || 0).toLocaleString();

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function cell(text, className) { return el("td", className, text); }

  function say(id, kind, message) {
    const box = $(id);
    box.className = "alert show " + kind;
    box.textContent = message;
  }

  function clearSay(id) {
    const box = $(id);
    if (!box) return;
    box.className = "alert";
    box.textContent = "";
  }

  function statusBadge(status) {
    const cls = status === "OPEN" ? "ok" : status === "CLOSED" ? "warn" : "";
    return el("span", "badge " + cls, status);
  }

  function emptyRow(body, cols, text) {
    const tr = document.createElement("tr");
    const td = el("td", "muted", text);
    td.colSpan = cols;
    tr.append(td);
    body.append(tr);
  }

  function addOption(select, value, text) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = text;
    select.append(option);
    return option;
  }

  function electionName(type) {
    const found = state.elections.find((e) => e.election_type === type);
    return found ? found.name : type;
  }

  function showError(error) {
    say("admin-alert", "error", error.message);
  }

  /* ---------- session ---------- */
  function forceLogout(message) {
    state.token = "";
    state.role = "";
    state.username = "";
    sessionStorage.removeItem(KEY);
    $("app").classList.add("hidden");
    $("login-card").classList.remove("hidden");
    if (message) say("login-alert", "warn", message);
  }

  async function doLogin() {
    const username = $("username").value.trim();
    const password = $("password").value;
    clearSay("login-alert");
    if (!username || !password) {
      return say("login-alert", "error", "Enter your username and password.");
    }
    const button = $("login-btn");
    button.disabled = true;
    try {
      const data = await api("/admin/login", { method: "POST", body: { username, password } });
      state.token = data.token;
      sessionStorage.setItem(KEY, data.token);
      $("password").value = "";
      await enterApp();
    } catch (error) {
      say("login-alert", "error", error.message);
    } finally {
      button.disabled = false;
    }
  }

  async function doLogout() {
    try { await api("/admin/logout", { method: "POST" }); } catch (_) { /* session may be gone */ }
    forceLogout("Signed out.");
  }

  function applyRole() {
    const allowed = ROLE_TABS[state.role] || ["overview"];
    document.querySelectorAll("#tabs [data-tab]").forEach((button) => {
      button.classList.toggle("hidden", !allowed.includes(button.dataset.tab));
    });
    document.querySelectorAll("[data-admin-only]").forEach((node) => {
      node.classList.toggle("hidden", state.role !== "ADMIN");
    });
    $("who").textContent = state.username + " · " + state.role;
  }

  async function enterApp() {
    const me = await api("/admin/me");
    state.username = me.username;
    state.role = me.role;
    applyRole();
    $("login-card").classList.add("hidden");
    $("app").classList.remove("hidden");
    $("admin-alert").className = "alert";
    $("admin-alert").textContent = "";
    showTab("overview");
  }

  const loaders = {
    overview: loadOverview,
    elections: loadElections,
    voters: () => loadVoters(),
    officers: loadOfficers,
    results: loadResults,
    audit: loadAudit,
  };

  function showTab(name) {
    const allowed = ROLE_TABS[state.role] || ["overview"];
    if (!allowed.includes(name)) name = "overview";
    document.querySelectorAll("#tabs [data-tab]").forEach((button) => {
      button.classList.toggle("active", button.dataset.tab === name);
    });
    document.querySelectorAll("[data-panel]").forEach((panel) => {
      panel.classList.toggle("hidden", panel.dataset.panel !== name);
    });
    clearSay("admin-alert");
    if (loaders[name]) loaders[name]();
  }

  /* ---------- overview ---------- */
  function chainBadge(id, chain) {
    const badge = $(id);
    badge.className = "badge " + (chain && chain.valid ? "ok" : "bad");
    if (chain && chain.valid) {
      badge.textContent = "Valid — " + fmt(chain.blocks_checked) + " block(s) checked";
    } else if (chain) {
      const at = chain.first_bad_block !== undefined ? " at block #" + chain.first_bad_block : "";
      badge.textContent = "FAILED" + (chain.reason ? " — " + chain.reason : "") + at;
    } else {
      badge.textContent = "Unknown";
    }
  }

  function auditLogBadge(id, check) {
    const badge = $(id);
    if (!check) {
      badge.className = "badge";
      badge.textContent = "Unknown";
    } else if (!check.valid) {
      const at = check.first_bad_entry !== undefined ? " at entry #" + check.first_bad_entry : "";
      badge.className = "badge bad";
      badge.textContent = "FAILED — " + (check.reason || "audit log mismatch") + at;
    } else if (!check.checkpoint) {
      badge.className = "badge warn";
      badge.textContent = "Chain valid — " + fmt(check.entries_checked) +
        " entries; no signed checkpoint yet, so truncation is not detectable";
    } else {
      const newer = Math.max(0, check.entries_checked - check.checkpoint.height);
      badge.className = "badge " + (newer ? "warn" : "ok");
      badge.textContent = newer
        ? "Valid for checkpoint height " + fmt(check.checkpoint.height) + "; " + fmt(newer) +
          " newer entr" + (newer === 1 ? "y is" : "ies are") +
          " not yet covered — sign a fresh checkpoint"
        : "Valid — " + fmt(check.entries_checked) + " entries; signature verified" +
          " at checkpoint height " + fmt(check.checkpoint.height);
    }
  }

  function resultCheckpointBadge(id, check) {
    const badge = $(id);
    if (!check) {
      badge.className = "badge";
      badge.textContent = "No checkpoint signed yet";
    } else if (check.valid && !check.all_sheets_covered) {
      badge.className = "badge warn";
      const newer = fmt(Math.max(0, check.sheets_present - check.tree_size));
      badge.textContent = "Valid for " + fmt(check.tree_size) + " sheet(s); " + newer +
        " newer sheet(s) not yet committed — sign a fresh checkpoint";
    } else if (check.valid) {
      badge.className = "badge ok";
      badge.textContent = "Valid — root and signature verified over all " +
        fmt(check.tree_size) + " sheet(s)";
    } else {
      badge.className = "badge bad";
      badge.textContent = "FAILED — " + (check.reason || "checkpoint mismatch");
    }
  }

  function checkpointBlock(title, cp, kind) {
    const wrap = el("div", "section");
    wrap.append(el("h3", "", title));
    if (!cp) {
      wrap.append(el("p", "muted", "No signed checkpoint yet."));
      return wrap;
    }
    let rows;
    if (kind === "ledger") {
      rows = [["Height", fmt(cp.height) + " ballots"], ["Head hash", cp.head_hash],
              ["Signature", cp.signature], ["Signed at", cp.created_at]];
    } else if (kind === "audit") {
      rows = [["Height", fmt(cp.height) + " audit entries"], ["Head hash", cp.head_hash],
              ["Signature", cp.signature], ["Signed at", cp.created_at]];
    } else {
      rows = [["Tree size", fmt(cp.tree_size) + " result sheets"], ["Merkle root", cp.root],
              ["Signature", cp.signature], ["Signed at", cp.created_at]];
    }
    const dl = document.createElement("dl");
    rows.forEach(([key, value]) => {
      dl.append(el("dt", "", key));
      const mono = /hash|root|signature/i.test(key);
      dl.append(el("dd", mono ? "mono" : "", value));
    });
    wrap.append(dl);
    return wrap;
  }

  async function loadOverview() {
    try {
      const s = await api("/admin/stats");
      $("ov-voters").textContent = fmt(s.voters);
      $("ov-votes").textContent = fmt(s.votes_cast);
      $("ov-open").textContent = fmt((s.open_elections || []).length);
      $("ov-sheets").textContent = fmt(s.result_sheets);
      $("ov-pending").textContent = fmt(s.pending_review);
      chainBadge("ledger-badge", s.ledger_chain);
      chainBadge("sheet-badge", s.sheet_chain);
      resultCheckpointBadge("result-cp-badge", s.result_checkpoint_check);
      auditLogBadge("audit-log-badge", s.audit_chain);
      const box = $("ov-checkpoints");
      box.replaceChildren(
        checkpointBlock("Vote ledger checkpoint", s.ledger_checkpoint, "ledger"),
        checkpointBlock("Result-sheet checkpoint", s.result_checkpoint, "sheet"),
        checkpointBlock("Admin audit-log checkpoint", s.audit_checkpoint, "audit"));
    } catch (error) {
      showError(error);
    }
  }

  async function signLedgerCheckpoint() {
    try {
      const cp = await api("/admin/audit/checkpoint", { method: "POST" });
      say("admin-alert", "ok", "Ledger checkpoint signed at height " + fmt(cp.height) + ".");
      if (!$("app").classList.contains("hidden")) await loadOverview();
    } catch (error) {
      showError(error);
    }
  }

  async function signAuditCheckpoint() {
    try {
      const cp = await api("/admin/audit/log-checkpoint", { method: "POST" });
      say("admin-alert", "ok", "Audit-log checkpoint signed at height " + fmt(cp.height) + ".");
      await loadOverview();
      await loadAudit();
    } catch (error) {
      showError(error);
    }
  }

  /* ---------- elections ---------- */
  async function loadElections() {
    const body = $("elections-body");
    body.replaceChildren();
    try {
      const data = await api("/admin/elections");
      state.elections = data.elections || [];
      if (!state.elections.length) return emptyRow(body, 3, "No elections configured.");
      state.elections.forEach((e) => {
        const tr = document.createElement("tr");
        const name = document.createElement("td");
        name.append(el("strong", "", e.name), el("div", "small muted", e.election_type));
        const status = document.createElement("td");
        status.append(statusBadge(e.status));
        tr.append(name, status, statusCell(e));
        body.append(tr);
      });
    } catch (error) {
      emptyRow(body, 3, error.message);
    }
  }

  function statusCell(election) {
    const td = document.createElement("td");
    td.className = "right";
    if (election.status === "PENDING") {
      td.append(actionButton("Open election", () => transition(election.election_type, "open")));
    } else if (election.status === "OPEN") {
      td.append(actionButton("Close election", () => transition(election.election_type, "close"), "danger"));
    } else {
      td.append(el("span", "muted", "Final"));
    }
    return td;
  }

  function actionButton(label, onClick, kind) {
    const button = el("button", "btn small" + (kind ? " " + kind : ""), label);
    button.type = "button";
    button.addEventListener("click", onClick);
    return button;
  }

  async function transition(type, action) {
    if (action === "close" && !confirm("Close " + electionName(type) +
      "? Results become public and voting can no longer reopen.")) return;
    try {
      await api("/admin/elections/" + encodeURIComponent(type) + "/" + action, { method: "POST" });
      say("admin-alert", "ok", "Election " + action + "ed.");
      await loadElections();
    } catch (error) {
      showError(error);
    }
  }

  /* ---------- voters ---------- */
  async function registerVoter() {
    const nin = $("v-nin").value.trim();
    const vin = $("v-vin").value.trim();
    const pu = $("v-pu").value.trim();
    const phone = $("v-phone").value.trim();
    clearSay("admin-alert");
    if (!/^\d{11}$/.test(nin)) return showError({ message: "NIN must be exactly 11 digits." });
    if (!/^[A-Za-z0-9]{6,20}$/.test(vin)) {
      return showError({ message: "VIN must be 6–20 letters or digits." });
    }
    if (!/^[A-Za-z0-9\-]{3,32}$/.test(pu)) {
      return showError({ message: "Polling unit code must be 3–32 letters, digits or hyphens." });
    }
    if (!/^\+\d{10,15}$/.test(phone)) {
      return showError({ message: "Phone must be in international format, e.g. +2348012345678." });
    }
    try {
      await api("/admin/voters", { method: "POST", body: {
        nin, vin, polling_unit_code: pu, phone_number: phone } });
      $("v-nin").value = "";
      $("v-vin").value = "";
      say("admin-alert", "ok", "Voter registered. Only a keyed hash was stored.");
      await loadVoters();
    } catch (error) {
      showError(error);
    }
  }

  async function loadVoters() {
    const body = $("voters-body");
    body.replaceChildren();
    try {
      const filter = $("v-filter").value.trim();
      const query = filter ? "?polling_unit_code=" + encodeURIComponent(filter) : "";
      const data = await api("/admin/voters" + query);
      const voters = data.voters || [];
      if (!voters.length) return emptyRow(body, 3, "No voters found.");
      voters.forEach((v) => {
        const tr = document.createElement("tr");
        tr.append(cell(v.reference, "mono"), cell(v.polling_unit_code), cell(v.phone));
        body.append(tr);
      });
    } catch (error) {
      emptyRow(body, 3, error.message);
    }
  }

  /* ---------- officers ---------- */
  async function ensureParties() {
    if (state.parties.length) return;
    const data = await api("/api/v1/elections");
    const seen = new Map();
    (data.elections || []).forEach((e) => (e.parties || []).forEach((p) => seen.set(p.code, p.name)));
    state.parties = Array.from(seen.entries());
    const select = $("o-party");
    select.replaceChildren();
    state.parties.forEach(([code, name]) => addOption(select, code, code + " — " + name));
  }

  async function loadOfficers() {
    const body = $("officers-body");
    body.replaceChildren();
    try {
      await ensureParties();
      const data = await api("/admin/officers");
      const officers = data.officers || [];
      if (!officers.length) return emptyRow(body, 6, "No officers registered.");
      officers.forEach((o) => {
        const tr = document.createElement("tr");
        const who = document.createElement("td");
        who.append(el("strong", "", o.name), el("div", "small muted", o.officer_id));
        const action = document.createElement("td");
        action.className = "right";
        action.append(actionButton(o.active ? "Deactivate" : "Activate",
          () => setOfficerState(o.officer_id, o.active ? "deactivate" : "activate"),
          o.active ? "secondary" : ""));
        tr.append(who, cell(o.role.replace("_", " ")), cell(o.polling_unit_code),
                  cell(o.party_code || "—"),
                  cell(""), action);
        tr.children[4].append(el("span", "badge " + (o.active ? "ok" : "bad"),
                                o.active ? "ACTIVE" : "INACTIVE"));
        body.append(tr);
      });
    } catch (error) {
      emptyRow(body, 6, error.message);
    }
  }

  async function addOfficer() {
    clearSay("admin-alert");
    const officerId = $("o-id").value.trim();
    const name = $("o-name").value.trim();
    const role = $("o-role").value;
    const pu = $("o-pu").value.trim();
    const key = $("o-key").value.trim().toLowerCase();
    if (!/^[A-Za-z0-9_.\-]{2,64}$/.test(officerId)) {
      return showError({ message: "Officer ID must be 2–64 letters, digits, dots, dashes or underscores." });
    }
    if (!name) return showError({ message: "Enter the officer's name." });
    if (!/^[A-Za-z0-9\-]{3,32}$/.test(pu)) {
      return showError({ message: "Polling unit code must be 3–32 letters, digits or hyphens." });
    }
    if (!/^[0-9a-f]{64}$/.test(key)) {
      return showError({ message: "Public key must be 64 hexadecimal characters." });
    }
    const body = { officer_id: officerId, name, role, polling_unit_code: pu, public_key: key,
                   party_code: role === "PARTY_AGENT" ? $("o-party").value : null };
    try {
      await api("/admin/officers", { method: "POST", body });
      $("o-key").value = "";
      say("admin-alert", "ok", "Officer registered.");
      await loadOfficers();
    } catch (error) {
      showError(error);
    }
  }

  async function setOfficerState(id, action) {
    try {
      await api("/admin/officers/" + encodeURIComponent(id) + "/" + action, { method: "POST" });
      say("admin-alert", "ok", "Officer " + action + "d.");
      await loadOfficers();
    } catch (error) {
      showError(error);
    }
  }

  /* ---------- results ---------- */
  async function loadResults() {
    try {
      await ensureElectionFilter();
      await loadResultCheckpoint();
      await loadAdminTally();
      await loadSheets();
    } catch (error) {
      showError(error);
    }
  }

  async function ensureElectionFilter() {
    const data = await api("/admin/elections");
    state.elections = data.elections || [];
    const select = $("res-election");
    const current = select.value;
    select.replaceChildren();
    addOption(select, "", "All elections");
    state.elections.forEach((e) => addOption(select, e.election_type, e.name));
    if (current && Array.from(select.options).some((o) => o.value === current)) {
      select.value = current;
    }
  }

  async function loadResultCheckpoint() {
    const box = $("result-cp");
    try {
      const data = await api("/results/checkpoint");
      if (!data.checkpoint) {
        box.replaceChildren(el("span", "muted", "No result-sheet checkpoint signed yet."));
        return;
      }
      const cp = data.checkpoint;
      const dl = document.createElement("dl");
      [["Tree size", fmt(cp.tree_size) + " result sheets"], ["Merkle root", cp.root],
       ["Signature", cp.signature], ["Authority public key", data.authority_public_key],
       ["Signed at", cp.created_at]].forEach(([key, value]) => {
        dl.append(el("dt", "", key));
        dl.append(el("dd", /root|signature|key/i.test(key) ? "mono" : "", value));
      });
      box.replaceChildren(dl);
    } catch (error) {
      box.replaceChildren(el("span", "muted", error.message));
    }
  }

  async function loadAdminTally() {
    const box = $("admin-tally");
    box.replaceChildren();
    try {
      const data = await api("/admin/tally");
      const closed = Object.entries(data.election_status || {}).filter(([, status]) => status === "CLOSED");
      if (!closed.length) {
        box.append(el("p", "muted", "No election has closed yet; tallies stay sealed."));
        return;
      }
      const grouped = {};
      (data.results || []).forEach((r) => {
        (grouped[r.election_type] = grouped[r.election_type] || []).push(r);
      });
      closed.forEach(([type]) => {
        const wrap = el("div", "section");
        wrap.append(el("h3", "", electionName(type) + " — closed tally"));
        const entries = grouped[type] || [];
        if (!entries.length) {
          wrap.append(el("p", "muted", "No counted votes."));
        } else {
          const tableWrap = el("div", "table-wrap");
          const table = document.createElement("table");
          const head = document.createElement("thead");
          const headRow = document.createElement("tr");
          ["Party", "Votes"].forEach((label) => headRow.append(el("th", "", label)));
          head.append(headRow);
          const body = document.createElement("tbody");
          entries.forEach((r) => {
            const tr = document.createElement("tr");
            tr.append(cell(r.party_code), cell(fmt(r.votes), "right"));
            body.append(tr);
          });
          table.append(head, body);
          tableWrap.append(table);
          wrap.append(tableWrap);
        }
        box.append(wrap);
      });
    } catch (error) {
      box.append(el("p", "muted", error.message));
    }
  }

  async function loadSheets() {
    const body = $("results-body");
    body.replaceChildren();
    try {
      const type = $("res-election").value;
      const data = await api("/admin/results" + (type ? "?election_type=" + encodeURIComponent(type) : ""));
      const sheets = data.sheets || [];
      if (!sheets.length) return emptyRow(body, 7, "No result sheets submitted.");
      sheets.forEach((s) => body.append(sheetRow(s)));
    } catch (error) {
      emptyRow(body, 7, error.message);
    }
  }

  function sheetRow(sheet) {
    const tr = document.createElement("tr");

    const idCell = cell(String(sheet.block_index), "mono");
    const what = document.createElement("td");
    what.append(el("strong", "", electionName(sheet.election_type)),
                el("div", "small muted", sheet.election_type + " · " + sheet.polling_unit_code));

    const flags = document.createElement("td");
    if ((sheet.flags || []).length) {
      sheet.flags.forEach((flag) => flags.append(el("span", "badge warn", flag), " "));
    } else {
      flags.append(el("span", "muted", "—"));
    }

    const review = document.createElement("td");
    const reviewClass = sheet.review_status === "ACCEPTED" ? "ok"
      : sheet.review_status === "VOID" ? "bad" : (sheet.flags || []).length ? "warn" : "";
    review.append(el("span", "badge " + reviewClass, sheet.review_status));
    if (sheet.reviewed_by) {
      review.append(el("div", "small muted", "by " + sheet.reviewed_by + " · " + sheet.reviewed_at));
    }
    if (sheet.review_note) review.append(el("div", "small", sheet.review_note));

    const action = document.createElement("td");
    const canReview = state.role === "ADMIN" && (sheet.flags || []).length &&
      sheet.review_status === "PENDING";
    if (canReview) {
      const box = el("div", "review-box");
      const note = document.createElement("input");
      note.type = "text";
      note.maxLength = 500;
      note.placeholder = "review note (optional)";
      note.setAttribute("aria-label", "Review note for " + sheet.polling_unit_code);
      box.append(note);
      box.append(actionButton("Accept", () => reviewSheet(sheet, "ACCEPT", note.value)));
      box.append(actionButton("Void", () => reviewSheet(sheet, "VOID", note.value), "danger"));
      action.append(box);
    } else {
      action.append(el("span", "muted", "—"));
    }

    tr.append(idCell, what, cell(sheet.officer_id), flags, review,
              cell(String(sheet.countersignatures), "right"), action);
    return tr;
  }

  async function reviewSheet(sheet, resolution, note) {
    if (resolution === "VOID" && !confirm("Void the sheet for " + sheet.polling_unit_code +
      "? It will be excluded from the tally.")) return;
    try {
      await api("/admin/results/" + encodeURIComponent(sheet.election_type) + "/" +
        encodeURIComponent(sheet.polling_unit_code) + "/review",
        { method: "POST", body: { resolution, note: note.trim() } });
      say("admin-alert", "ok", "Sheet " + (resolution === "ACCEPT" ? "accepted" : "voided") + ".");
      await loadResults();
    } catch (error) {
      showError(error);
    }
  }

  async function signResultCheckpoint() {
    try {
      const cp = await api("/results/checkpoint", { method: "POST" });
      say("admin-alert", "ok", "Result checkpoint signed over " + fmt(cp.tree_size) + " sheet(s).");
      await loadResultCheckpoint();
    } catch (error) {
      showError(error);
    }
  }

  async function exportResults() {
    try {
      await download("/admin/results/export", "evoting-results-export.json");
      say("admin-alert", "ok", "Archive downloaded. Verify it with verify_offline.py.");
    } catch (error) {
      showError(error);
    }
  }

  /* ---------- audit ---------- */
  async function loadAudit() {
    const body = $("audit-body");
    body.replaceChildren();
    try {
      const data = await api("/admin/audit");
      const rows = data.audit || [];
      if (!rows.length) return emptyRow(body, 4, "No audit entries yet.");
      rows.forEach((entry) => {
        const tr = document.createElement("tr");
        tr.append(cell(entry.ts, "small nowrap"), cell(entry.actor),
                  cell(entry.action), cell(entry.detail || ""));
        body.append(tr);
      });
    } catch (error) {
      emptyRow(body, 4, error.message);
    }
  }

  async function verifyVoteChain() {
    try {
      const result = await api("/admin/audit/verify-chain");
      if (result.valid) {
        say("chain-result", "ok", "Vote ledger verified: " + fmt(result.blocks_checked) +
          " block(s), head " + result.head + ".");
      } else {
        say("chain-result", "error", "Vote ledger FAILED verification" +
          (result.first_bad_block !== undefined ? " at block #" + result.first_bad_block : "") +
          (result.reason ? " (" + result.reason + ")" : "") + ".");
      }
    } catch (error) {
      say("chain-result", "error", error.message);
    }
  }

  async function verifyAuditLog() {
    try {
      const result = await api("/admin/audit/verify-log");
      if (!result.valid) {
        say("audit-log-result", "error", "Audit log FAILED verification" +
          (result.first_bad_entry !== undefined ? " at entry #" + result.first_bad_entry : "") +
          (result.reason ? " (" + result.reason + ")" : "") + ".");
      } else if (!result.checkpoint) {
        say("audit-log-result", "warn", "Audit-log chain is valid over " +
          fmt(result.entries_checked) + " entries, but no signed checkpoint exists; " +
          "truncation cannot be detected. Sign an audit-log checkpoint.");
      } else {
        say("audit-log-result", "ok", "Audit log verified: " + fmt(result.entries_checked) +
          " entries, checkpoint height " + fmt(result.checkpoint.height) +
          ", head " + result.head + ".");
      }
    } catch (error) {
      say("audit-log-result", "error", error.message);
    }
  }

  async function exportLedger() {
    try {
      await download("/admin/audit/export", "evoting-ledger.json");
      say("admin-alert", "ok", "Vote ledger downloaded.");
    } catch (error) {
      showError(error);
    }
  }

  /* ---------- wiring ---------- */
  $("login-btn").addEventListener("click", doLogin);
  $("password").addEventListener("keydown", (event) => {
    if (event.key === "Enter") doLogin();
  });
  $("username").addEventListener("keydown", (event) => {
    if (event.key === "Enter") $("password").focus();
  });
  $("logout-btn").addEventListener("click", doLogout);

  $("tabs").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-tab]");
    if (button) showTab(button.dataset.tab);
  });

  $("refresh-overview").addEventListener("click", loadOverview);
  $("sign-ledger-cp").addEventListener("click", signLedgerCheckpoint);
  $("sign-ledger-cp-2").addEventListener("click", signLedgerCheckpoint);
  $("refresh-elections").addEventListener("click", loadElections);
  $("register-voter-btn").addEventListener("click", registerVoter);
  $("load-voters-btn").addEventListener("click", () => loadVoters());
  $("v-filter").addEventListener("keydown", (event) => {
    if (event.key === "Enter") loadVoters();
  });
  $("o-role").addEventListener("change", () => {
    $("o-party-field").classList.toggle("hidden", $("o-role").value !== "PARTY_AGENT");
  });
  $("add-officer-btn").addEventListener("click", addOfficer);
  $("refresh-officers").addEventListener("click", loadOfficers);
  $("load-results-btn").addEventListener("click", loadResults);
  $("refresh-results-btn").addEventListener("click", loadResults);
  $("res-election").addEventListener("change", loadSheets);
  $("sign-result-cp").addEventListener("click", signResultCheckpoint);
  $("export-results-btn").addEventListener("click", exportResults);
  $("refresh-audit").addEventListener("click", loadAudit);
  $("verify-chain-btn").addEventListener("click", verifyVoteChain);
  $("verify-audit-log-btn").addEventListener("click", verifyAuditLog);
  $("sign-audit-cp").addEventListener("click", signAuditCheckpoint);
  $("export-ledger-btn").addEventListener("click", exportLedger);

  async function boot() {
    $("login-card").classList.remove("hidden");
    if (!state.token) return;
    try {
      await enterApp();
    } catch (_) {
      /* forceLogout already returned to the sign-in card */
    }
  }

  boot();
})();
