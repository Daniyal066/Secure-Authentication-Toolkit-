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
        
        // Dynamic icons based on status type
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

    // --- Real-time Password Strength Auditor (Register Tab) ---
    const regPassword = document.getElementById("reg-password");
    const strengthLabel = document.getElementById("strength-label");
    const strengthBar = document.getElementById("strength-bar");
    const regSubmitBtn = document.getElementById("register-submit-btn");

    // UI Requirement targets
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
            
            // Evaluators
            const checks = {
                len: password.length >= 8,
                upper: /[A-Z]/.test(password),
                lower: /[a-z]/.test(password),
                digit: /\d/.test(password),
                special: /[!@#$%^&*(),.?":{}|<>]/.test(password)
            };

            let passedCount = 0;

            // Update individual bullet item styling
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

            // Assign strength level based on criteria met
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
                regSubmitBtn.disabled = false; // Allow medium passwords
            } else {
                strengthLabel.textContent = "Weak";
                strengthLabel.className = "strength-tag weak";
                strengthBar.className = "progress-bar-fill weak";
                regSubmitBtn.disabled = true; // Reject weak passwords
            }
        });
    }

    // --- User Registration API Fetch ---
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
                    // Reset strength meter UI
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

    // --- User Login API Fetch ---
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

    // --- Password Generator Slider & Logic ---
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
            try {
                const response = await fetch("/api/generate-password", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ length })
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

    // --- Copy Generated Password to Clipboard ---
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

    // --- Fetch Logs ---
    const logsTableBody = document.getElementById("logs-table-body");
    const refreshLogsBtn = document.getElementById("refresh-logs-btn");

    async function fetchLogs() {
        if (!logsTableBody) return;
        logsTableBody.innerHTML = `<tr><td colspan="4" class="text-center">Loading logs...</td></tr>`;

        try {
            const response = await fetch("/api/logs");
            const data = await response.json();
            
            if (response.ok && data.success) {
                if (data.logs.length === 0) {
                    logsTableBody.innerHTML = `<tr><td colspan="4" class="text-center">No logs recorded yet.</td></tr>`;
                    return;
                }
                
                logsTableBody.innerHTML = "";
                data.logs.forEach(log => {
                    const tr = document.createElement("tr");
                    
                    // Assign class depending on status text for color highlights
                    let badgeClass = "badge";
                    const statusLower = log.status.toLowerCase();
                    if (statusLower.includes("success")) badgeClass += " success";
                    else if (statusLower.includes("fail")) badgeClass += " failed";
                    else if (statusLower.includes("lock")) badgeClass += " locked";
                    else if (statusLower.includes("regist")) badgeClass += " registration";
                    
                    tr.innerHTML = `
                        <td>${log.timestamp}</td>
                        <td><strong>${escapeHtml(log.username)}</strong></td>
                        <td><span class="${badgeClass}">${escapeHtml(log.status)}</span></td>
                        <td>${escapeHtml(log.info)}</td>
                    `;
                    logsTableBody.appendChild(tr);
                });
            } else {
                logsTableBody.innerHTML = `<tr><td colspan="4" class="text-center text-error">Failed to load logs.</td></tr>`;
            }
        } catch (err) {
            logsTableBody.innerHTML = `<tr><td colspan="4" class="text-center text-error">Server communication error.</td></tr>`;
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
