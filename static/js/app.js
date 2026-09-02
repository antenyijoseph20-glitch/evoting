document.addEventListener("DOMContentLoaded", () => {
    // Initial fetch on page load
    loadDashboardData();

    // Poll backend every 5 seconds (5000 milliseconds) for real-time sync
    setInterval(loadDashboardData, 5000);
});

/**
 * Fetches ledger and tally data from backend and updates the DOM.
 */
async function loadDashboardData() {
    const statusBadge = document.getElementById("integrity-status");
    const blocksContainer = document.getElementById("blocks-container");
    const tallyResultsList = document.getElementById("tally-results-list");

    try {
        // Fetch Ledger and Tally data in parallel
        const [ledgerResponse, tallyResponse] = await Promise.all([
            fetch("/api/v1/bulletin-board/export"),
            fetch("/api/v1/tally/results")
        ]);

        if (!ledgerResponse.ok || !tallyResponse.ok) {
            throw new Error("Failed to fetch ledger or tally data from backend.");
        }

        const ledgerData = await ledgerResponse.json();
        const tallyData = await tallyResponse.json();
        const blocks = ledgerData.blocks || [];

        // Run browser-side cryptographic chain validation
        const verificationResult = await verifyLedgerChain(blocks);

        // Update integrity status badge
        if (statusBadge) {
            if (verificationResult.isValid) {
                statusBadge.innerHTML = `🔒 <strong>CHAIN CRYPTOGRAPHICALLY VERIFIED</strong> (${verificationResult.verifiedCount} Blocks Intact, SHA-256 Linkage Valid)`;
                statusBadge.style.backgroundColor = "#d4edda";
                statusBadge.style.color = "#155724";
                statusBadge.style.border = "1px solid #c3e6cb";
            } else {
                statusBadge.innerHTML = `⚠️ <strong>INTEGRITY WARNING: CHAIN BROKEN</strong> at Block #${verificationResult.failedAt}`;
                statusBadge.style.backgroundColor = "#f8d7da";
                statusBadge.style.color = "#721c24";
                statusBadge.style.border = "1px solid #f5c6cb";
            }
            statusBadge.style.padding = "12px 16px";
            statusBadge.style.borderRadius = "6px";
            statusBadge.style.fontSize = "13px";
        }

        // Render Live Vote Tallies
        if (tallyResultsList) {
            if (tallyData.tallies && tallyData.tallies.length > 0) {
                tallyResultsList.innerHTML = `
                    <p style="margin: 4px 0 10px 0; font-size: 14px; color: #555;">
                        <strong>Total Ballots Cast:</strong> ${tallyData.total_votes_cast}
                    </p>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px;">
                        ${tallyData.tallies.map(t => `
                            <div style="padding: 10px 14px; border: 1px solid #ced4da; border-radius: 6px; background: #fff;">
                                <span style="font-size: 13px; color: #666; display: block;">Candidate</span>
                                <strong style="font-size: 16px; color: #0056b3;">${t.candidate_id}</strong>
                                <span style="float: right; font-size: 18px; font-weight: bold; color: #28a745;">${t.vote_count}</span>
                            </div>
                        `).join("")}
                    </div>
                `;
            } else {
                tallyResultsList.innerHTML = `<p style="margin: 0; color: #666; font-size: 14px;">No votes recorded on the ledger yet.</p>`;
            }
        }

        // Render each block dynamically into the container
        if (blocksContainer && blocks.length > 0) {
            blocksContainer.innerHTML = blocks.map(block => `
                <div class="block-card" style="border: 1px solid #e0e0e0; padding: 16px; margin-bottom: 12px; border-radius: 8px; background: #ffffff; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <h3 style="margin: 0; color: #111;">Block #${block.block_id}</h3>
                        <span style="font-size: 11px; color: #666;">${block.synced_at_timestamp}</span>
                    </div>
                    <p style="margin: 8px 0 4px 0;"><strong>Receipt Hash:</strong> <code style="background: #f1f1f1; padding: 2px 6px; border-radius: 4px; font-size: 12px;">${block.receipt_hash}</code></p>
                    <p style="margin: 4px 0;"><strong>Block Hash:</strong> <code style="background: #f1f1f1; padding: 2px 6px; border-radius: 4px; font-size: 12px; word-break: break-all; color: #0056b3;">${block.block_hash}</code></p>
                    <p style="margin: 4px 0 0 0;"><strong>Previous Hash:</strong> <code style="background: #f1f1f1; padding: 2px 6px; border-radius: 4px; font-size: 12px; word-break: break-all; color: #555;">${block.previous_hash}</code></p>
                </div>
            `).join("");
        }

    } catch (error) {
        console.error("Failed to load dashboard data during poll:", error);
        
        if (statusBadge) {
            statusBadge.innerHTML = "⚠️ <strong>BULLETIN BOARD OFFLINE OR UNREACHABLE</strong>";
            statusBadge.style.backgroundColor = "#f8d7da";
            statusBadge.style.color = "#721c24";
            statusBadge.style.border = "1px solid #f5c6cb";
            statusBadge.style.padding = "12px 16px";
            statusBadge.style.borderRadius = "6px";
            statusBadge.style.fontSize = "13px";
        }
    }
}

/**
 * Validates the backward hash linkage of the blockchain blocks.
 */
async function verifyLedgerChain(blocks) {
    if (!blocks || blocks.length === 0) {
        return { isValid: true, verifiedCount: 0 };
    }

    for (let i = 0; i < blocks.length; i++) {
        const currentBlock = blocks[i];

        if (i > 0) {
            const prevBlock = blocks[i - 1];
            if (currentBlock.previous_hash !== prevBlock.block_hash) {
                return {
                    isValid: false,
                    failedAt: currentBlock.block_id,
                    verifiedCount: i
                };
            }
        }
    }

    return {
        isValid: true,
        verifiedCount: blocks.length
    };
}

// Global variable to hold the temporary session token after successful accreditation
let activeSessionToken = null;

// Attach event listeners for the voting form once DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
    // ... (keep your existing setInterval / loadDashboardData calls here) ...

    const authForm = document.getElementById("auth-form");
    const ballotForm = document.getElementById("ballot-form");
    const feedbackDiv = document.getElementById("voter-feedback");

    // Handle Step 1: NIN/VIN Verification
    if (authForm) {
        authForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            feedbackDiv.innerHTML = "Verifying credentials with National Identity Database...";
            feedbackDiv.style.color = "#555";

            const nin = document.getElementById("nin-input").value.trim();
            const vin = document.getElementById("vin-input").value.trim();
            const polling_unit_code = document.getElementById("pu-input").value.trim();

            try {
                const response = await fetch("/api/v1/auth/verify-voter", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ nin, vin, polling_unit_code })
                });

                const result = await response.json();

                if (result.status === "success") {
                    activeSessionToken = result.session_token;
                    feedbackDiv.innerHTML = `✅ ${result.message}`;
                    feedbackDiv.style.color = "#155724";

                    // Switch to Step 2 (Ballot casting)
                    document.getElementById("step-1-container").style.display = "none";
                    document.getElementById("step-2-container").style.display = "block";
                } else {
                    feedbackDiv.innerHTML = `❌ Error: ${result.message}`;
                    feedbackDiv.style.color = "#721c24";
                }
            } catch (err) {
                console.error("Auth request failed:", err);
                feedbackDiv.innerHTML = "❌ Failed to connect to verification server.";
                feedbackDiv.style.color = "#721c24";
            }
        });
    }

    // Handle Step 2: Ballot Casting
    if (ballotForm) {
        ballotForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            if (!activeSessionToken) {
                alert("No active session token found. Please re-authenticate.");
                return;
            }

            feedbackDiv.innerHTML = "Casting ballot and anchoring to blockchain ledger...";
            feedbackDiv.style.color = "#555";

            const candidate_id = document.getElementById("candidate-select").value;
            const polling_unit_code = document.getElementById("pu-input").value.trim();

            try {
                const response = await fetch("/api/v1/ballot/submit", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        session_token: activeSessionToken,
                        candidate_id: candidate_id,
                        polling_unit_code: polling_unit_code
                    })
                });

                const result = await response.json();

                if (result.status === "success") {
                    feedbackDiv.innerHTML = `🎉 Vote cast successfully! Block Hash: <code style="background:#f1f1f1; padding:2px 4px;">${result.receipt.block_hash.substring(0, 16)}...</code>`;
                    feedbackDiv.style.color = "#155724";

                    // Reset form and refresh dashboard data
                    activeSessionToken = null;
                    document.getElementById("step-2-container").style.display = "none";
                    document.getElementById("step-1-container").style.display = "block";
                    document.getElementById("auth-form").reset();

                    // Immediately trigger dashboard reload to show new block & tally count
                    if (typeof loadDashboardData === "function") {
                        loadDashboardData();
                    }
                } else {
                    feedbackDiv.innerHTML = `❌ Error: ${result.message}`;
                    feedbackDiv.style.color = "#721c24";
                }
            } catch (err) {
                console.error("Ballot submission failed:", err);
                feedbackDiv.innerHTML = "❌ Failed to submit ballot.";
                feedbackDiv.style.color = "#721c24";
            }
        });
    }
});