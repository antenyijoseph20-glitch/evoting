"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const PANELS = [1, 2, 3, 4, 5];
  const state = {
    token: null,
    credentials: null,
    elections: [],
    receipt: null,
    stream: null,
  };

  function setStep(n) {
    PANELS.forEach((i) => $("panel-" + i).classList.toggle("hidden", i !== n));
    document.querySelectorAll("#steps li").forEach((li) => {
      const s = Number(li.dataset.step);
      li.classList.toggle("active", s === n);
      li.classList.toggle("done", s < n);
    });
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

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
      const error = new Error(explain(data) || ("Request failed (HTTP " + response.status + ")."));
      error.status = response.status;
      throw error;
    }
    return data;
  }

  const authHeaders = () => ({ Authorization: "Bearer " + state.token });

  function restart(message) {
    stopCamera();
    state.token = null;
    state.credentials = null;
    state.receipt = null;
    setStep(1);
    if (message) say("alert-1", "warn", message);
  }

  /* ---------- elections ---------- */
  async function loadElections() {
    try {
      const data = await api("/api/v1/elections");
      state.elections = data.elections || [];
      const open = state.elections.filter((e) => e.status === "OPEN");
      const select = $("election");
      select.replaceChildren();
      if (!open.length) {
        select.disabled = true;
        $("btn-cast").disabled = true;
        $("election-hint").textContent = "No election is open right now. Check the public results page for status.";
        $("party").replaceChildren();
        return;
      }
      open.forEach((e) => {
        const option = document.createElement("option");
        option.value = e.election_type;
        option.textContent = e.name;
        select.appendChild(option);
      });
      select.disabled = false;
      $("btn-cast").disabled = false;
      $("election-hint").textContent = "Only elections currently open are listed.";
      populateParties();
    } catch (error) {
      $("election-hint").textContent = "Could not load elections: " + error.message;
    }
  }

  function populateParties() {
    const election = state.elections.find((e) => e.election_type === $("election").value);
    const select = $("party");
    select.replaceChildren();
    (election ? election.parties : []).forEach((p) => {
      const option = document.createElement("option");
      option.value = p.code;
      option.textContent = p.code + " — " + p.name;
      select.appendChild(option);
    });
  }

  /* ---------- camera ---------- */
  async function startCamera() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      say("alert-3", "info", "This browser cannot open a camera. Upload a photo instead.");
      return;
    }
    try {
      state.stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "user", width: { ideal: 640 } },
        audio: false,
      });
      $("cam").srcObject = state.stream;
    } catch (_) {
      say("alert-3", "info", "Camera permission was denied or no camera is available. Upload a photo instead.");
    }
  }

  function stopCamera() {
    if (state.stream) {
      state.stream.getTracks().forEach((track) => track.stop());
      state.stream = null;
    }
    $("cam").srcObject = null;
  }

  async function uploadFace(blob, button) {
    const form = new FormData();
    form.append("file", blob, "face.jpg");
    button.disabled = true;
    clearSay("alert-3");
    try {
      await api("/api/v1/biometric/verify-face", {
        method: "POST", headers: authHeaders(), body: form,
      });
      stopCamera();
      setStep(4);
      await loadElections();
    } catch (error) {
      if (error.status === 401) restart("Your session expired. Start again from identity.");
      else say("alert-3", "error", error.message);
    } finally {
      button.disabled = false;
    }
  }

  /* ---------- step 1 ---------- */
  $("btn-verify").addEventListener("click", async () => {
    const nin = $("nin").value.trim();
    const vin = $("vin").value.trim();
    clearSay("alert-1");
    if (!/^\d{11}$/.test(nin)) return say("alert-1", "error", "NIN must be exactly 11 digits.");
    if (!/^[A-Za-z0-9]{6,20}$/.test(vin)) return say("alert-1", "error", "Enter a valid VIN (6–20 letters or digits).");
    const button = $("btn-verify");
    button.disabled = true;
    try {
      const data = await api("/api/v1/auth/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ nin, vin }),
      });
      state.token = data.session_token;
      state.credentials = { nin, vin };
      $("otp-lede").textContent = "A code was sent to " + data.phone + ". It expires in " +
        Math.round(data.otp_expires_in_seconds / 60) + " minutes.";
      $("nin").value = "";
      $("vin").value = "";
      $("otp").value = "";
      clearSay("alert-2");
      setStep(2);
      $("otp").focus();
    } catch (error) {
      say("alert-1", "error", error.message);
    } finally {
      button.disabled = false;
    }
  });

  /* ---------- step 2 ---------- */
  async function requestOtp() {
    if (!state.credentials) {
      restart();
      return false;
    }
    const button = $("btn-resend");
    button.disabled = true;
    clearSay("alert-2");
    try {
      const data = await api("/api/v1/auth/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(state.credentials),
      });
      state.token = data.session_token;
      $("otp").value = "";
      say("alert-2", "ok", "A new code was sent to " + data.phone + ".");
      return true;
    } catch (error) {
      say("alert-2", "error", error.message);
      return false;
    } finally {
      button.disabled = false;
    }
  }

  $("btn-resend").addEventListener("click", requestOtp);

  $("btn-otp").addEventListener("click", async () => {
    const code = $("otp").value.trim();
    clearSay("alert-2");
    if (!/^\d{6}$/.test(code)) return say("alert-2", "error", "Enter the 6-digit code.");
    const button = $("btn-otp");
    button.disabled = true;
    try {
      await api("/api/v1/auth/verify-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({ otp_code: code }),
      });
      setStep(3);
      startCamera();
    } catch (error) {
      say("alert-2", "error", error.message);
    } finally {
      button.disabled = false;
    }
  });

  $("otp").addEventListener("keydown", (event) => {
    if (event.key === "Enter") $("btn-otp").click();
  });

  /* ---------- step 3 ---------- */
  $("btn-capture").addEventListener("click", async () => {
    const video = $("cam");
    if (!video.videoWidth) return say("alert-3", "error", "Camera is not ready yet. Wait a moment or upload a photo.");
    const canvas = $("snap");
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    canvas.getContext("2d").drawImage(video, 0, 0);
    const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/jpeg", 0.9));
    if (!blob) return say("alert-3", "error", "Could not capture the frame. Try again.");
    await uploadFace(blob, $("btn-capture"));
  });

  $("photo").addEventListener("change", async () => {
    const file = $("photo").files[0];
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) {
      $("photo").value = "";
      return say("alert-3", "error", "Photo is larger than 2 MB. Choose a smaller image.");
    }
    await uploadFace(file, $("btn-capture"));
  });

  /* ---------- step 4 ---------- */
  $("election").addEventListener("change", populateParties);

  $("btn-cast").addEventListener("click", async () => {
    const election = $("election").value;
    const party = $("party").value;
    clearSay("alert-4");
    if (!election || !party) return say("alert-4", "error", "Choose an election and a party.");
    const button = $("btn-cast");
    button.disabled = true;
    try {
      const data = await api("/api/v1/ballot/cast", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({ election_type: election, party_code: party }),
      });
      state.receipt = data.receipt;
      renderReceipt();
      setStep(5);
    } catch (error) {
      if (error.status === 401) restart("Your session expired. Start again from identity.");
      else say("alert-4", "error", error.message);
    } finally {
      button.disabled = false;
    }
  });

  /* ---------- step 5 ---------- */
  function renderReceipt() {
    const receipt = state.receipt;
    const list = document.createElement("dl");
    const rows = [
      ["Election", receipt.election_type],
      ["Block index", String(receipt.block_index)],
      ["Block hash", receipt.block_hash],
    ];
    rows.forEach(([label, value]) => {
      const dt = document.createElement("dt");
      dt.textContent = label;
      const dd = document.createElement("dd");
      dd.textContent = value;
      if (label === "Block hash") dd.className = "mono";
      list.append(dt, dd);
    });
    $("receipt").replaceChildren(list);
  }

  $("btn-check").addEventListener("click", async () => {
    if (!state.receipt) return;
    clearSay("alert-5");
    const button = $("btn-check");
    button.disabled = true;
    try {
      const data = await api("/api/v1/receipt/" + encodeURIComponent(state.receipt.block_hash));
      if (data.chain && data.chain.valid) {
        const checkpoint = data.latest_checkpoint
          ? ", and the ledger reaches the latest signed checkpoint (height " +
            data.latest_checkpoint.height + ")"
          : ", and no signed checkpoint has been published yet";
        say("alert-5", "ok", "Receipt found in block #" + data.block.block_index +
          ". The ledger chain verified (" + data.chain.blocks_checked + " blocks" + checkpoint + ").");
      } else {
        say("alert-5", "error", "Receipt found, but the ledger chain failed verification. Contact an auditor.");
      }
    } catch (error) {
      say("alert-5", "error", error.message);
    } finally {
      button.disabled = false;
    }
  });

  window.addEventListener("beforeunload", stopCamera);

  loadElections();
  $("nin").focus();
})();
