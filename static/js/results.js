"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const state = { elections: [], selected: null, partyNames: {} };

  function explain(data) {
    if (!data || !data.detail) return "Request failed.";
    if (typeof data.detail === "string") return data.detail;
    if (Array.isArray(data.detail)) return data.detail.map((e) => e.msg || "").join(", ");
    return "Request failed.";
  }

  async function api(url, options) {
    const response = await fetch(url, options || {});
    let data = null;
    try { data = await response.json(); } catch (_) { /* no body */ }
    if (!response.ok) {
      const error = new Error(explain(data));
      error.status = response.status;
      throw error;
    }
    return data;
  }

  const fmt = (n) => Number(n || 0).toLocaleString();
  const pct = (n, total) => (total ? ((n / total) * 100).toFixed(1) : "0.0") + "%";

  function say(id, kind, message) {
    const box = $(id);
    box.className = "alert show " + kind;
    box.textContent = message;
  }

  function clearSay(id) {
    const box = $(id);
    box.className = "alert";
    box.textContent = "";
  }

  function badge(status) {
    const span = document.createElement("span");
    const cls = status === "OPEN" ? "ok" : status === "CLOSED" ? "warn" : "";
    span.className = "badge " + cls;
    span.textContent = status;
    return span;
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  /* ---------- elections ---------- */
  async function loadElections() {
    try {
      const data = await api("/api/v1/elections");
      state.elections = data.elections || [];
      const select = $("election");
      select.replaceChildren();
      state.elections.forEach((e) => {
        const option = document.createElement("option");
        option.value = e.election_type;
        option.textContent = e.name;
        select.appendChild(option);
      });
      const preferred = state.elections.find((e) => e.status === "CLOSED") ||
        state.elections.find((e) => e.status === "OPEN") || state.elections[0];
      if (preferred) {
        select.value = preferred.election_type;
        selectElection();
      }
    } catch (error) {
      $("election-status").replaceChildren(el("span", "badge bad", "Unavailable"));
      $("election-status").append(" " + error.message);
    }
  }

  function selectElection() {
    const type = $("election").value;
    state.selected = state.elections.find((e) => e.election_type === type) || null;
    state.partyNames = {};
    if (state.selected) {
      state.selected.parties.forEach((p) => { state.partyNames[p.code] = p.name; });
    }
    render();
  }

  async function render() {
    const election = state.selected;
    const statusBox = $("election-status");
    statusBox.replaceChildren();
    if (!election) return;
    statusBox.append(badge(election.status), " ");
    statusBox.append(el("span", "small muted",
      election.status === "OPEN" ? "Voting is in progress. Vote totals are sealed."
        : election.status === "CLOSED" ? "Voting has closed. Counted results are published below."
        : "This election has not been opened."));

    $("live-section").classList.toggle("hidden", election.status === "CLOSED");
    $("tally-section").classList.toggle("hidden", election.status !== "CLOSED");

    if (election.status === "CLOSED") {
      await loadTally(election);
    } else {
      await loadLiveStatus(election);
    }
    await loadProofIfPossible();
  }

  async function loadLiveStatus(election) {
    try {
      const data = await api("/results/status/" + encodeURIComponent(election.election_type));
      $("live-sheets").textContent = fmt(data.sheets_submitted);
      $("live-flagged").textContent = fmt(data.flagged);
      $("live-pending").textContent = fmt(data.pending_review);
      $("live-note").textContent = data.status === "OPEN"
        ? "Vote totals and party figures are withheld until the election is closed."
        : "Voting has not started. Results will appear after the election opens and closes.";
    } catch (error) {
      $("live-note").textContent = error.message;
    }
  }

  async function loadTally(election) {
    try {
      const data = await api("/results/tally/" + encodeURIComponent(election.election_type));
      const entries = Object.entries(data.totals || {});
      const total = entries.reduce((sum, [, n]) => sum + n, 0);
      $("hero-value").textContent = fmt(total);
      $("hero-sub").textContent = election.name + " · " + data.sheets_counted +
        " polling unit" + (data.sheets_counted === 1 ? "" : "s") + " counted";
      $("stat-sheets").textContent = fmt(data.sheets_counted);
      $("stat-accredited").textContent = fmt(data.total_accredited);
      $("stat-parties").textContent = fmt(entries.filter(([, n]) => n > 0).length);
      renderChart(entries, total);
      renderTallyTable(entries, total);
      renderFlagNotes(data);
    } catch (error) {
      $("hero-value").textContent = "—";
      $("hero-sub").textContent = error.message;
      $("tally-chart").replaceChildren();
      $("tally-table-body").replaceChildren();
      $("tally-notes").replaceChildren();
    }
  }

  function renderChart(entries, total) {
    const chart = $("tally-chart");
    chart.replaceChildren();
    if (!entries.length) {
      chart.append(el("p", "muted", "No votes have been counted for this election yet."));
      return;
    }
    entries.forEach(([party, votes]) => {
      const share = total ? (votes / total) * 100 : 0;
      const row = el("div", "bar-row");
      row.tabIndex = 0;
      const name = el("div", "bar-name");
      name.append(el("span", "swatch"));
      const code = el("strong", "", party);
      const full = el("small", "", state.partyNames[party] || party);
      name.append(code, full);
      const track = el("div", "bar-track");
      const fill = el("div", "bar-fill");
      fill.style.width = share.toFixed(2) + "%";
      track.append(fill);
      const value = el("div", "bar-value", fmt(votes) + " ");
      value.append(el("span", "pct", "(" + share.toFixed(1) + "%)"));
      row.append(name, track, value);

      const tipText = party + " — " + (state.partyNames[party] || party) +
        ": " + fmt(votes) + " votes (" + pct(votes, total) + " of counted)";
      row.setAttribute("aria-label", tipText);
      const show = () => showTip(row, tipText);
      row.addEventListener("mouseenter", show);
      row.addEventListener("focus", show);
      row.addEventListener("mouseleave", hideTip);
      row.addEventListener("blur", hideTip);
      chart.append(row);
    });
  }

  function showTip(row, text) {
    const chart = $("tally-chart");
    const tip = $("chart-tip");
    const r = row.getBoundingClientRect();
    const c = chart.getBoundingClientRect();
    tip.textContent = text;
    tip.style.left = (r.left - c.left + r.width / 2) + "px";
    tip.style.top = (r.top - c.top) + "px";
    tip.classList.add("show");
  }

  function hideTip() {
    $("chart-tip").classList.remove("show");
  }

  function renderTallyTable(entries, total) {
    const body = $("tally-table-body");
    body.replaceChildren();
    if (!entries.length) {
      const tr = document.createElement("tr");
      const td = el("td", "", "No votes counted.");
      td.colSpan = 4;
      tr.append(td);
      body.append(tr);
      return;
    }
    entries.forEach(([party, votes]) => {
      const tr = document.createElement("tr");
      tr.append(el("td", "", party), el("td", "", state.partyNames[party] || party),
                el("td", "right", fmt(votes)), el("td", "right", pct(votes, total)));
      body.append(tr);
    });
  }

  function renderFlagNotes(data) {
    const box = $("tally-notes");
    box.replaceChildren();
    const add = (title, items, kind) => {
      if (!items || !items.length) return;
      const wrap = el("div", "section");
      wrap.append(el("h3", "", title));
      const ul = el("ul", "flag-list");
      items.forEach((item) => {
        const detail = item.reason || (item.flags || []).join(", ");
        ul.append(el("li", "", item.polling_unit_code + " — " + detail));
      });
      wrap.append(ul);
      if (kind === "muted") wrap.classList.add("muted");
      box.append(wrap);
    };
    add("Flagged sheets excluded pending review", data.flagged_excluded);
    add("Flagged sheets accepted after review", data.flagged_accepted);
    add("Sheets voided after review", data.voided);
    add("Sheets excluded because stored data failed verification", data.invalid_sheets);
  }

  /* ---------- checkpoint & proofs ---------- */
  async function loadCheckpoint() {
    const box = $("checkpoint-body");
    try {
      const data = await api("/results/checkpoint");
      if (!data.checkpoint) {
        box.replaceChildren(el("span", "muted", "No checkpoint has been signed yet."));
        return;
      }
      const cp = data.checkpoint;
      const dl = document.createElement("dl");
      const rows = [
        ["Tree size", fmt(cp.tree_size) + " signed result sheets"],
        ["Merkle root", cp.root],
        ["Checkpoint signature", cp.signature],
        ["Authority public key", data.authority_public_key],
        ["Signed at", cp.created_at],
      ];
      rows.forEach(([k, v]) => {
        dl.append(el("dt", "", k));
        const dd = el("dd", k.includes("root") || k.includes("signature") || k.includes("key") ? "mono" : "", v);
        dl.append(dd);
      });
      box.replaceChildren(dl);
    } catch (error) {
      box.replaceChildren(el("span", "muted", error.message));
    }
  }

  async function loadProofIfPossible() {
    const box = $("proof-result");
    box.classList.add("hidden");
    box.replaceChildren();
    $("proof-pu").value = "";
  }

  $("proof-btn").addEventListener("click", async () => {
    const election = state.selected;
    const pu = $("proof-pu").value.trim();
    const box = $("proof-result");
    if (!election) return;
    if (!pu) {
      box.classList.remove("hidden");
      box.replaceChildren(el("span", "muted", "Enter a polling unit code."));
      return;
    }
    box.classList.remove("hidden");
    box.replaceChildren(el("span", "muted", "Fetching proof…"));
    try {
      const data = await api("/results/proof/" + encodeURIComponent(election.election_type) +
        "/" + encodeURIComponent(pu));
      const dl = document.createElement("dl");
      const rows = [
        ["Leaf hash", data.leaf],
        ["Leaf index", String(data.leaf_index)],
        ["Tree size", fmt(data.tree_size)],
        ["Merkle root", data.root],
        ["Audit path", data.path.length ? data.path.join("\n") : "(single-leaf tree)"],
        ["Checkpoint signature", data.checkpoint_signature],
        ["Authority public key", data.authority_public_key],
      ];
      rows.forEach(([k, v]) => {
        dl.append(el("dt", "", k));
        const mono = /hash|root|path|signature|key/i.test(k);
        dl.append(el("dd", mono ? "mono" : "", v));
      });
      box.replaceChildren(dl);
    } catch (error) {
      box.replaceChildren(el("span", "muted", error.message));
    }
  });

  $("export-link").addEventListener("click", async (event) => {
    event.preventDefault();
    clearSay("export-note");
    try {
      const data = await api("/results/export");
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "evoting-export.json";
      document.body.append(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      say("export-note", "ok", "Archive downloaded. Verify it with verify_offline.py.");
    } catch (error) {
      say("export-note", "warn", error.message + " It unlocks once no election is open.");
    }
  });

  /* ---------- public ledger ---------- */
  async function sha256Hex(text) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  async function verifyVisibleChain(blocks) {
    let prev = "0".repeat(64);
    for (const block of blocks) {
      if (block.previous_hash !== prev) return { valid: false, at: block.block_index };
      const expected = await sha256Hex(JSON.stringify(
        [prev, block.election_type, block.party_code, block.polling_unit_code]));
      if (expected !== block.block_hash) return { valid: false, at: block.block_index };
      prev = block.block_hash;
    }
    return { valid: true, head: prev };
  }

  async function loadLedger() {
    const summary = $("ledger-summary");
    const body = $("ledger-table-body");
    try {
      const data = await api("/api/v1/audit/ledger");
      summary.replaceChildren();
      const tiles = [
        ["Ledger height", fmt(data.ledger_height), "ballots recorded"],
        ["Published blocks", fmt(data.visible_blocks), "closed elections only"],
        ["Server chain check", data.chain.valid ? "Valid" : "Broken", data.chain.valid ?
          (data.chain.blocks_checked + " blocks verified") :
          (data.chain.reason || ("first bad block " + data.chain.first_bad_block))],
      ];
      tiles.forEach(([k, v, s]) => {
        const tile = el("div", "stat");
        tile.append(el("div", "k", k), el("div", "v", v), el("div", "s", s));
        summary.append(tile);
      });

      let note = data.chain.valid ? "Server-side hash-chain verification passed." : "Chain verification FAILED.";
      if (data.checkpoint) {
        note += " Latest signed checkpoint: height " + fmt(data.checkpoint.height) + ".";
      }
      if (data.visible_blocks === data.ledger_height && data.visible_blocks > 0) {
        if (crypto.subtle) {
          try {
            const local = await verifyVisibleChain(data.blocks);
            note += local.valid
              ? " Browser re-computation of every block hash passed."
              : " Browser re-computation FAILED at block " + local.at + ".";
          } catch (_) {
            note += " Browser re-computation could not run.";
          }
        } else {
          note += " Browser re-computation requires a secure (HTTPS) context.";
        }
      } else {
        note += " Browser recomputation of the full chain is available once no election is open.";
      }
      $("ledger-note").textContent = note;

      body.replaceChildren();
      if (!data.blocks.length) {
        const tr = document.createElement("tr");
        const td = el("td", "muted", "No blocks are published yet. Blocks appear after an election closes.");
        td.colSpan = 5;
        tr.append(td);
        body.append(tr);
      }
      data.blocks.forEach((block) => {
        const tr = document.createElement("tr");
        const hashCell = document.createElement("td");
        hashCell.append(el("span", "mono", block.block_hash));
        tr.append(el("td", "", String(block.block_index)), el("td", "", block.election_type),
                  el("td", "", block.party_code), el("td", "", block.polling_unit_code), hashCell);
        body.append(tr);
      });
    } catch (error) {
      summary.replaceChildren(el("div", "stat", error.message));
      $("ledger-note").textContent = "";
    }
  }

  /* ---------- receipt ---------- */
  $("receipt-btn").addEventListener("click", async () => {
    const hash = $("receipt-hash").value.trim().toLowerCase();
    clearSay("receipt-result");
    if (!/^[0-9a-f]{64}$/.test(hash)) {
      return say("receipt-result", "error", "Receipt hash must be 64 hexadecimal characters.");
    }
    try {
      const data = await api("/api/v1/receipt/" + encodeURIComponent(hash));
      if (data.chain.valid) {
        const checkpoint = data.latest_checkpoint
          ? " The ledger reaches the latest signed checkpoint (height " +
            data.latest_checkpoint.height + ")."
          : " No signed ledger checkpoint has been published yet.";
        say("receipt-result", "ok", "Receipt found in block #" + data.block.block_index +
          " (" + data.block.election_type + "). The ledger chain verified across " +
          data.chain.blocks_checked + " blocks." + checkpoint);
      } else {
        say("receipt-result", "error", "Receipt found, but the ledger chain failed verification. Contact an auditor.");
      }
    } catch (error) {
      say("receipt-result", error.status === 404 ? "warn" : "error", error.message);
    }
  });

  $("receipt-hash").addEventListener("keydown", (event) => {
    if (event.key === "Enter") $("receipt-btn").click();
  });

  $("election").addEventListener("change", selectElection);

  loadElections();
  loadCheckpoint();
  loadLedger();
})();
