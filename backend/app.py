from collections import Counter
from flask import Flask, jsonify, request
import re

app = Flask(__name__)

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[[^\]]+\]\s+'
    r'"(?P<method>[A-Z]+)\s+'
    r'(?P<path>\S+)\s+[^"]+"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
)

SUSPICIOUS_PATTERNS = [
    (r'\.\./', "Path traversal attempt"),
    (r'/\.env(?:\b|/|$)', "Environment file access"),
    (r'/etc/passwd', "Sensitive file access"),
    (r'union\s+select', "Possible SQL injection"),
    (r'<script', "Possible XSS attempt"),
    (r'wp-admin|wp-login\.php', "WordPress endpoint probe"),
]


def analyze_logs(log_text):
    entries = []
    findings = []
    invalid_lines = 0

    for line_number, line in enumerate(log_text.splitlines(), start=1):
        if not line.strip():
            continue

        match = LOG_PATTERN.search(line)
        if not match:
            invalid_lines += 1
            continue

        data = match.groupdict()
        status = int(data["status"])
        path = data["path"]

        entry = {
            "line": line_number,
            "ip": data["ip"],
            "method": data["method"],
            "path": path,
            "status": status,
        }
        entries.append(entry)

        if status in (401, 403):
            findings.append({
                **entry,
                "severity": "Medium",
                "reason": "Authentication or access denied",
            })
        elif status >= 500:
            findings.append({
                **entry,
                "severity": "High",
                "reason": "Server error",
            })

        for pattern, reason in SUSPICIOUS_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                findings.append({
                    **entry,
                    "severity": "High",
                    "reason": reason,
                })

    failed_logins = Counter(
        entry["ip"] for entry in entries if entry["status"] == 401
    )

    for ip, count in failed_logins.items():
        if count >= 5:
            findings.append({
                "line": None,
                "ip": ip,
                "method": "-",
                "path": "-",
                "status": 401,
                "severity": "High",
                "reason": f"{count} unauthorized responses from one IP",
            })

    findings.sort(
        key=lambda item: {"High": 0, "Medium": 1}.get(item["severity"], 2)
    )

    status_counts = Counter(str(entry["status"]) for entry in entries)

    return {
        "total_requests": len(entries),
        "successful_requests": sum(e["status"] < 400 for e in entries),
        "client_errors": sum(400 <= e["status"] < 500 for e in entries),
        "server_errors": sum(e["status"] >= 500 for e in entries),
        "invalid_lines": invalid_lines,
        "status_counts": dict(status_counts),
        "unique_ips": len({e["ip"] for e in entries}),
        "findings": findings,
        "entries": entries,
    }


@app.get("/api/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/api/analyze")
def analyze():
    data = request.get_json(silent=True) or {}
    log_text = data.get("logs", "")

    if not isinstance(log_text, str):
        return jsonify({"error": "Logs must be text."}), 400

    if not log_text.strip():
        return jsonify({"error": "Please provide log entries."}), 400

    if len(log_text) > 1_000_000:
        return jsonify({"error": "Maximum input size is 1 MB."}), 413

    return jsonify(analyze_logs(log_text))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
