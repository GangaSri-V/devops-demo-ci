const logInput = document.getElementById("logInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const sampleBtn = document.getElementById("sampleBtn");
const lineCount = document.getElementById("lineCount");
const message = document.getElementById("message");
const results = document.getElementById("results");

const sampleLogs = `192.168.1.10 - - [05/Oct/2026:09:10:00 +0000] "GET / HTTP/1.1" 200 1200
192.168.1.11 - - [05/Oct/2026:09:11:00 +0000] "GET /login HTTP/1.1" 200 800
203.0.113.25 - - [05/Oct/2026:09:12:00 +0000] "POST /login HTTP/1.1" 401 300
203.0.113.25 - - [05/Oct/2026:09:12:05 +0000] "POST /login HTTP/1.1" 401 300
203.0.113.25 - - [05/Oct/2026:09:12:10 +0000] "POST /login HTTP/1.1" 401 300
203.0.113.25 - - [05/Oct/2026:09:12:15 +0000] "POST /login HTTP/1.1" 401 300
203.0.113.25 - - [05/Oct/2026:09:12:20 +0000] "POST /login HTTP/1.1" 401 300
198.51.100.42 - - [05/Oct/2026:09:13:00 +0000] "GET /.env HTTP/1.1" 403 200
192.168.1.10 - - [05/Oct/2026:09:14:00 +0000] "GET /dashboard HTTP/1.1" 500 400`;

function updateLineCount() {
    const count = logInput.value.split("\\n").filter(line => line.trim()).length;
    lineCount.textContent = `${count} lines`;
}

logInput.addEventListener("input", updateLineCount);

sampleBtn.addEventListener("click", () => {
    logInput.value = sampleLogs;
    updateLineCount();
    message.textContent = "";
});

analyzeBtn.addEventListener("click", analyzeLogs);

async function analyzeLogs() {
    const logs = logInput.value.trim();

    if (!logs) {
        message.textContent = "Please enter some log entries first.";
        return;
    }

    analyzeBtn.disabled = true;
    analyzeBtn.textContent = "Analyzing...";
    message.textContent = "";

    try {
        const response = await fetch("/api/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ logs })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Analysis failed.");
        }

        renderResults(data);
        results.hidden = false;
        message.textContent = "Analysis completed successfully.";
        results.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
        message.textContent = `Could not analyze logs: ${error.message}`;
    } finally {
        analyzeBtn.disabled = false;
        analyzeBtn.textContent = "Analyze logs →";
    }
}

function renderResults(data) {
    document.getElementById("total").textContent = data.total_requests;
    document.getElementById("successful").textContent = data.successful_requests;
    document.getElementById("clientErrors").textContent = data.client_errors;
    document.getElementById("serverErrors").textContent = data.server_errors;
    document.getElementById("uniqueIps").textContent = data.unique_ips;
    document.getElementById("invalidLines").textContent = data.invalid_lines;
    document.getElementById("findingCount").textContent =
        `${data.findings.length} findings`;
    document.getElementById("findingSummary").textContent =
        data.findings.length
            ? "Review the potential issues below."
            : "No configured rules were triggered.";

    renderFindings(data.findings);
    renderStatusCounts(data.status_counts);
}

function renderFindings(findings) {
    const tbody = document.getElementById("findingsBody");
    tbody.replaceChildren();

    if (findings.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.colSpan = 5;
        cell.className = "empty-row";
        cell.textContent = "No findings for the configured rules.";
        row.appendChild(cell);
        tbody.appendChild(row);
        return;
    }

    for (const finding of findings) {
        const row = document.createElement("tr");
        const values = [
            finding.severity,
            finding.ip,
            `${finding.method} ${finding.path}`,
            finding.status,
            finding.reason
        ];

        values.forEach((value, index) => {
            const cell = document.createElement("td");
            cell.textContent = value;

            if (index === 0) {
                cell.className = `severity ${finding.severity.toLowerCase()}`;
            }

            row.appendChild(cell);
        });

        tbody.appendChild(row);
    }
}

function renderStatusCounts(counts) {
    const container = document.getElementById("statusDistribution");
    container.replaceChildren();

    for (const [status, count] of Object.entries(counts)) {
        const item = document.createElement("div");
        item.className = "status-item";

        const label = document.createElement("strong");
        label.textContent = status;

        const value = document.createElement("span");
        value.textContent = ` — ${count} requests`;

        item.append(label, value);
        container.appendChild(item);
    }
}

async function checkBackend() {
    try {
        const response = await fetch("/api/health");
        if (!response.ok) throw new Error("Backend health check failed.");
    } catch {
        message.textContent =
            "Cannot reach the backend. Check whether Flask is running.";
    }
}

checkBackend();
