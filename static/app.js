document.addEventListener("DOMContentLoaded", () => {
    // --- Navigation Tabs ---
    const tabs = document.querySelectorAll(".tab-btn");
    const panels = document.querySelectorAll(".tab-panel");

    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            tabs.forEach(t => t.classList.remove("active"));
            panels.forEach(p => p.classList.remove("active"));

            tab.classList.add("active");
            const activePanel = document.getElementById(tab.dataset.tab);
            if (activePanel) {
                activePanel.classList.add("active");
            }

            // Auto-refresh logs when viewing the logs tab
            if (tab.id === "view-logs-btn") {
                fetchLogs();
            }
        });
    });

    // --- Toast Alert Notification ---
    const toast = document.getElementById("status-toast");
    const toastMsg = document.getElementById("toast-message");
    let toastTimeout;

    function showToast(message, type = "success") {
        clearTimeout(toastTimeout);
        toastMsg.textContent = message;
        toast.className = `toast ${type}`;
        
        const icon = toast.querySelector(".toast-icon");
        if (type === "success") {
            icon.className = "fa-solid fa-circle-check toast-icon";
        } else {
            icon.className = "fa-solid fa-circle-exclamation toast-icon";
        }

        toastTimeout = setTimeout(() => {
            toast.className = "toast hidden";
        }, 5000);
    }

    // --- Real-time Password Strength Auditor (Register Tab - Module 1) ---
    const regPassword = document.getElementById("reg-password");
    const strengthLabel = document.getElementById("strength-label");
    const strengthBar = document.getElementById("strength-bar");
    const regSubmitBtn = document.getElementById("register-submit-btn");

    const reqs = {
        len: document.getElementById("req-len"),
        upper: document.getElementById("req-upper"),
        lower: document.getElementById("req-lower"),
        digit: document.getElementById("req-digit"),
        special: document.getElementById("req-special")
    };

    if (regPassword) {
        regPassword.addEventListener("input", () => {
            const password = regPassword.value;
            
            const checks = {
                len: password.length >= 8,
                upper: /[A-Z]/.test(password),
                lower: /[a-z]/.test(password),
                digit: /\d/.test(password),
                special: /[!@#$%^&*(),.?\":{}|<>]/.test(password)
            };

            let passedCount = 0;

            for (const key in checks) {
                if (checks[key]) {
                    reqs[key].className = "valid";
                    reqs[key].querySelector("i").className = "fa-solid fa-circle-check";
                    passedCount++;
                } else {
                    reqs[key].className = "invalid";
                    reqs[key].querySelector("i").className = "fa-solid fa-circle-xmark";
                }
            }

            if (password.length === 0) {
                strengthLabel.textContent = "None";
                strengthLabel.className = "strength-tag weak";
                strengthBar.className = "progress-bar-fill w-0";
                regSubmitBtn.disabled = true;
            } else if (passedCount === 5) {
                strengthLabel.textContent = "Strong";
                strengthLabel.className = "strength-tag strong";
                strengthBar.className = "progress-bar-fill strong";
                regSubmitBtn.disabled = false;
            } else if (passedCount >= 3) {
                strengthLabel.textContent = "Medium";
                strengthLabel.className = "strength-tag medium";
                strengthBar.className = "progress-bar-fill medium";
                regSubmitBtn.disabled = false;
            } else {
                strengthLabel.textContent = "Weak";
                strengthLabel.className = "strength-tag weak";
                strengthBar.className = "progress-bar-fill weak";
                regSubmitBtn.disabled = true;
            }
        });
    }

    // --- User Registration (Module 1) ---
    const registerForm = document.getElementById("register-form");
    if (registerForm) {
        registerForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const username = document.getElementById("reg-username").value;
            const password = regPassword.value;

            try {
                const response = await fetch("/api/register", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ username, password })
                });

                const data = await response.json();
                if (response.ok) {
                    showToast(data.message, "success");
                    registerForm.reset();
                    strengthLabel.textContent = "None";
                    strengthLabel.className = "strength-tag weak";
                    strengthBar.className = "progress-bar-fill w-0";
                    for (const key in reqs) {
                        reqs[key].className = "invalid";
                        reqs[key].querySelector("i").className = "fa-solid fa-circle-xmark";
                    }
                    regSubmitBtn.disabled = true;
                } else {
                    showToast(data.message, "error");
                }
            } catch (err) {
                showToast("Connection error: Unable to contact server.", "error");
            }
        });
    }

    // --- User Login & Account Lockout (Module 2) ---
    const loginForm = document.getElementById("login-form");
    if (loginForm) {
        loginForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const username = document.getElementById("login-username").value;
            const password = document.getElementById("login-password").value;

            try {
                const response = await fetch("/api/login", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ username, password })
                });

                const data = await response.json();
                if (response.ok) {
                    showToast(data.message, "success");
                    loginForm.reset();
                } else {
                    showToast(data.message, "error");
                }
            } catch (err) {
                showToast("Connection error: Unable to contact server.", "error");
            }
        });
    }

    // --- Secure Password Generator (Module 3) ---
    const slider = document.getElementById("pass-length");
    const sliderLabel = document.getElementById("length-val");
    if (slider) {
        slider.addEventListener("input", () => {
            sliderLabel.textContent = slider.value;
        });
    }

    const generateBtn = document.getElementById("generate-btn");
    const outputContainer = document.getElementById("gen-output-container");
    const generatedPass = document.getElementById("generated-password");
    const explanationList = document.getElementById("generator-explanations-list");

    if (generateBtn) {
        generateBtn.addEventListener("click", async () => {
            const length = slider.value;
            
            // Read checkboxes states
            const uppercase = document.getElementById("gen-upper").checked;
            const lowercase = document.getElementById("gen-lower").checked;
            const digits = document.getElementById("gen-digits").checked;
            const special = document.getElementById("gen-special").checked;

            try {
                const response = await fetch("/api/generate-password", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ length, uppercase, lowercase, digits, special })
                });
                
                const data = await response.json();
                if (response.ok) {
                    generatedPass.value = data.password;
                    explanationList.innerHTML = "";
                    data.explanation.forEach(exp => {
                        const li = document.createElement("li");
                        li.textContent = exp;
                        explanationList.appendChild(li);
                    });
                    outputContainer.classList.remove("hidden");
                } else {
                    showToast("Failed to generate password.", "error");
                }
            } catch (err) {
                showToast("Failed to generate password due to server error.", "error");
            }
        });
    }

    // --- Copy Generated Password ---
    const copyBtn = document.getElementById("copy-btn");
    if (copyBtn) {
        copyBtn.addEventListener("click", () => {
            if (generatedPass && generatedPass.value) {
                generatedPass.select();
                navigator.clipboard.writeText(generatedPass.value)
                    .then(() => {
                        showToast("Password copied to clipboard!", "success");
                    })
                    .catch(() => {
                        showToast("Failed to copy password automatically.", "error");
                    });
            }
        });
    }

    // --- Threat & Attack Analyzer (Modules 4 & 5) ---
    const logsInput = document.getElementById("analyzer-logs-input");
    const loadMockBtn = document.getElementById("load-mock-btn");
    const analyzeBtn = document.getElementById("analyze-btn");
    const analysisResults = document.getElementById("analysis-results");
    
    // Outputs
    const totalProcessed = document.getElementById("summary-total-processed");
    const totalIpAlerts = document.getElementById("summary-ip-alerts");
    const totalUserAlerts = document.getElementById("summary-user-alerts");
    const ipAlertsList = document.getElementById("ip-alerts-list");
    const userAlertsList = document.getElementById("user-alerts-list");

    // Load mock log templates
    if (loadMockBtn) {
        loadMockBtn.addEventListener("click", () => {
            const mockLogs = [
                "# Timestamp | IP Address | Username | Password Tried | Action Status",
                "[2026-07-30 15:01:00] IP: 192.168.1.50 | User: admin | Status: Failed | Info: Password attempted: Password123",
                "[2026-07-30 15:01:15] IP: 192.168.1.50 | User: admin | Status: Failed | Info: Password attempted: admin2026",
                "[2026-07-30 15:01:30] IP: 192.168.1.50 | User: admin | Status: Locked | Info: Password attempted: rootpassword",
                "[2026-07-30 15:02:10] IP: 10.0.0.8 | User: alice | Status: Success | Info: Successful login.",
                "[2026-07-30 15:03:00] IP: 203.0.113.12 | User: sreehas | Status: Failed | Info: Password attempted: sreehas123",
                "[2026-07-30 15:03:12] IP: 203.0.113.12 | User: sreehas | Status: Failed | Info: Password attempted: testing99",
                "[2026-07-30 15:03:30] IP: 203.0.113.12 | User: sreehas | Status: Failed | Info: Password attempted: override_security!",
                "[2026-07-30 15:05:00] IP: 192.168.1.88 | User: bob | Status: Failed | Info: Password attempted: testpass",
                "[2026-07-30 15:06:00] IP: 192.168.1.88 | User: bob | Status: Success | Info: Successful login."
            ].join("\n");
            
            logsInput.value = mockLogs;
            showToast("Mock attack logs loaded. Ready for analysis!", "success");
        });
    }

    if (analyzeBtn) {
        analyzeBtn.addEventListener("click", async () => {
            const logsText = logsInput.value.trim();
            if (!logsText) {
                showToast("Please enter or load log data first.", "error");
                return;
            }

            try {
                const response = await fetch("/api/analyze-logs", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ logs: logsText })
                });

                const data = await response.json();
                if (response.ok && data.success) {
                    // Update Summary
                    totalProcessed.textContent = data.total_processed;
                    totalIpAlerts.textContent = data.brute_force_alerts.length;
                    totalUserAlerts.textContent = data.password_guessing_alerts.length;

                    // 1. Render Module 4: Brute Force IP Alerts
                    ipAlertsList.innerHTML = "";
                    if (data.brute_force_alerts.length === 0) {
                        ipAlertsList.innerHTML = `<div class="no-alerts">No brute force attacks detected.</div>`;
                    } else {
                        data.brute_force_alerts.forEach(alert => {
                            const item = document.createElement("div");
                            item.className = "alert-item";
                            item.innerHTML = `
                                <div class="alert-item-header">
                                    <span class="alert-target"><i class="fa-solid fa-triangle-exclamation"></i> IP: ${escapeHtml(alert.ip)}</span>
                                    <span class="alert-badge critical">${escapeHtml(alert.severity)}</span>
                                </div>
                                <div class="alert-desc">${escapeHtml(alert.explanation)}</div>
                                <div class="alert-meta">Failed login events from IP: <strong>${alert.failed_attempts}</strong></div>
                            `;
                            ipAlertsList.appendChild(item);
                        });
                    }

                    // 2. Render Module 5: Password Guessing Accounts Alerts
                    userAlertsList.innerHTML = "";
                    if (data.password_guessing_alerts.length === 0) {
                        userAlertsList.innerHTML = `<div class="no-alerts">No password guessing attacks detected.</div>`;
                    } else {
                        data.password_guessing_alerts.forEach(alert => {
                            const item = document.createElement("div");
                            item.className = "alert-item warning-state";
                            item.innerHTML = `
                                <div class="alert-item-header">
                                    <span class="alert-target"><i class="fa-solid fa-shield-virus"></i> Account: ${escapeHtml(alert.username)}</span>
                                    <span class="alert-badge high">${escapeHtml(alert.severity)}</span>
                                </div>
                                <div class="alert-desc">${escapeHtml(alert.explanation)}</div>
                                <div class="alert-meta">
                                    Unique passwords tried: <strong>${alert.unique_passwords_attempted}</strong><br>
                                    Attempted passwords: <code style="word-break: break-all;">${alert.passwords.map(p => escapeHtml(p)).join(", ")}</code>
                                </div>
                            `;
                            userAlertsList.appendChild(item);
                        });
                    }

                    analysisResults.classList.remove("hidden");
                    showToast("Log analysis completed successfully!", "success");
                } else {
                    showToast("Failed to parse log contents.", "error");
                }
            } catch (err) {
                showToast("Server communication error during analysis.", "error");
            }
        });
    }

    // --- Fetch Logs ---
    const logsTableBody = document.getElementById("logs-table-body");
    const refreshLogsBtn = document.getElementById("refresh-logs-btn");

    async function fetchLogs() {
        if (!logsTableBody) return;
        logsTableBody.innerHTML = `<tr><td colspan="5" class="text-center">Loading logs...</td></tr>`;

        try {
            const response = await fetch("/api/logs");
            const data = await response.json();
            
            if (response.ok && data.success) {
                if (data.logs.length === 0) {
                    logsTableBody.innerHTML = `<tr><td colspan="5" class="text-center">No logs recorded yet.</td></tr>`;
                    return;
                }
                
                logsTableBody.innerHTML = "";
                data.logs.forEach(log => {
                    const tr = document.createElement("tr");
                    
                    let badgeClass = "badge";
                    const statusLower = log.status.toLowerCase();
                    if (statusLower.includes("success")) badgeClass += " success";
                    else if (statusLower.includes("fail")) badgeClass += " failed";
                    else if (statusLower.includes("lock")) badgeClass += " locked";
                    else if (statusLower.includes("regist")) badgeClass += " registration";
                    
                    tr.innerHTML = `
                        <td>${log.timestamp}</td>
                        <td><code>${escapeHtml(log.ip)}</code></td>
                        <td><strong>${escapeHtml(log.username)}</strong></td>
                        <td><span class="${badgeClass}">${escapeHtml(log.status)}</span></td>
                        <td>${escapeHtml(log.info)}</td>
                    `;
                    logsTableBody.appendChild(tr);
                });
            } else {
                logsTableBody.innerHTML = `<tr><td colspan="5" class="text-center text-error">Failed to load logs.</td></tr>`;
            }
        } catch (err) {
            logsTableBody.innerHTML = `<tr><td colspan="5" class="text-center text-error">Server communication error.</td></tr>`;
        }
    }

    if (refreshLogsBtn) {
        refreshLogsBtn.addEventListener("click", fetchLogs);
    }

    // Safe input strings escape helper
    function escapeHtml(str) {
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});
