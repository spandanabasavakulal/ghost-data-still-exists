#!/usr/bin/env python3
"""
Ghost Data Still Exists - evidence-led deletion audit generator.
Run from the project root:
    python code/main.py
Writes output.csv with one row per dataset/deletion_requests.csv case.
"""
import csv
import json
import re
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "dataset"
OUT = DATA / "output.csv"

RESOURCE_RE = re.compile(r"\b(account|search|analytics|support|export|backup|data_flow|audit_record|tombstone|integration|marketing|cache|telemetry|secondary_identifier|delivery_log|support_attachment|user_export|profile)_\d+\b", re.I)
PREFIX_SYSTEM = {
    "account": "account_service", "search": "search_service",
    "analytics": "analytics_platform", "support": "support_platform",
    "export": "export_service", "backup": "backup_service",
    "data_flow": "integration_service", "integration": "integration_service",
    "audit_record": "security_service", "tombstone": "identity_service",
    "marketing": "marketing_service", "cache": "cache_service",
    "telemetry": "telemetry_service", "secondary_identifier": "identity_service",
    "delivery_log": "email_service", "support_attachment": "support_platform",
    "user_export": "export_service", "profile": "account_service",
}
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OP_ORDER = {
    "REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2, "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1, "DELETE_RECORD": 2,
    "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0, "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2, "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4, "VERIFY_RESTORE_BLOCKED": 5,
}

def parse_time(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None

def read_csv(path):
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))

def file_evidence():
    meta = {r["file_path"].replace("\\", "/"): r for r in read_csv(DATA / "evidence_files.csv")}
    evidence = []
    for rel, row in meta.items():
        path = DATA / rel
        if not path.exists():
            continue
        suffix = path.suffix.lower()
        if suffix not in {".json", ".sql", ".log", ".txt"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        item = {
            "id": row["file_id"], "time": parse_time(row.get("captured_at", "")),
            "path": path, "text": text, "rel": rel,
            "lines": text.splitlines(), "records": []
        }
        if suffix == ".json":
            try:
                obj = json.loads(text)
                def collect(node):
                    found = []
                    if isinstance(node, dict):
                        if any(k in node for k in ("resource_id", "customer_reference", "subject_reference")):
                            found.append(node)
                        for v in node.values():
                            found.extend(collect(v))
                    elif isinstance(node, list):
                        for v in node:
                            found.extend(collect(v))
                    return found
                item["records"] = collect(obj)
            except Exception:
                pass
        evidence.append(item)
    return evidence

def exact_hit(text, values):
    low = text.casefold()
    for value in values:
        value = (value or "").strip()
        if not value:
            continue
        if "@" in value:
            # Email must be a full token; case-insensitive.
            if re.search(r"(?<![A-Z0-9._%+\-])" + re.escape(value) + r"(?![A-Z0-9._%+\-])", text, re.I):
                return True
        elif re.fullmatch(r"user_\d+", value, re.I):
            if re.search(r"(?<![A-Z0-9_])" + re.escape(value) + r"(?!\d)", text, re.I):
                return True
        elif value.casefold() in low:
            return True
    return False

def extract_records(ev):
    """Yield small record-like objects from JSON; line parsing handles logs and SQL."""
    return ev.get("records", [])

def aliases_for(email, identities, audit):
    aliases = {email.strip().lower()}
    users = set()
    for row in identities:
        if row.get("email", "").strip().lower() == email.strip().lower():
            users.add(row.get("user_id", ""))
            if row.get("email_hash"):
                aliases.add(row["email_hash"].strip().lower())
    # Include historical email aliases only for the same resolved user.
    for row in audit:
        if row.get("user_id") in users and row.get("field_name", "").lower() in {"email", "email_address", "emailaddress"}:
            for v in (row.get("old_value", ""), row.get("new_value", "")):
                if "@" in v:
                    aliases.add(v.strip().lower())
    return aliases, users

def resource_type(resource):
    m = re.match(r"([A-Za-z_]+)_\d+$", resource or "")
    return m.group(1).lower() if m else ""


def build_evidence_index(evidence):
    index = {}
    email_re = re.compile(r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}", re.I)
    user_re = re.compile(r"\buser_\d+\b", re.I)
    for ev in evidence:
        chunks = []
        for line in ev["lines"]:
            ids = RESOURCE_RE.findall(line)
            # RESOURCE_RE returns only the prefix capture; extract full IDs separately.
            rids = re.findall(r"\b(?:account|search|analytics|support|export|backup|data_flow|audit_record|tombstone|integration|marketing|cache|telemetry|secondary_identifier|delivery_log|support_attachment|user_export|profile)_\d+\b", line, re.I)
            if not rids:
                continue
            keys = set(x.lower() for x in email_re.findall(line))
            keys.update(x.lower() for x in user_re.findall(line))
            for key in keys:
                for rid in set(rids):
                    index.setdefault(key, {}).setdefault(rid, []).append((ev, line, None))
        for rec in ev.get("records", []):
            serialized = json.dumps(rec, ensure_ascii=False)
            rid = rec.get("resource_id")
            if not rid:
                continue
            keys = set(x.lower() for x in email_re.findall(serialized))
            keys.update(x.lower() for x in user_re.findall(serialized))
            for key in keys:
                index.setdefault(key, {}).setdefault(rid, []).append((ev, serialized, rec))
    return index

def build_case(case, evidence, identities, audit, evidence_index):
    email = case["email"].strip()
    audit_at = parse_time(case.get("audit_at", ""))
    aliases, users = aliases_for(email, identities, audit)
    match_values = set(aliases) | users
    # Look up only evidence records indexed by exact email/user identifiers.
    hits = {}
    for key in match_values:
        for rid, entries in evidence_index.get(key.lower(), {}).items():
            for entry in entries:
                ev = entry[0]
                if audit_at and ev["time"] and ev["time"] > audit_at:
                    continue
                hits.setdefault(rid, []).append(entry)
    # Prefer latest evidence per resource; skip evidence captured after audit_at.
    current = {}
    for rid, entries in hits.items():
        entries.sort(key=lambda x: (x[0]["time"] or datetime.min.replace(tzinfo=timezone.utc), x[0]["id"]))
        current[rid] = entries[-1]
    steps = []
    findings = []
    for rid, (ev, snippet, rec) in current.items():
        typ = resource_type(rid)
        system = PREFIX_SYSTEM.get(typ)
        if not system:
            continue
        txt = (snippet or "").lower()
        if typ == "account":
            op, state = "REPORT_REMAINING_RECORD", "PRESENT"
            remop, remstate, verop, vers = "DELETE_RECORD", "ABSENT", "VERIFY_RECORD_ABSENT", "ABSENT"
        elif typ in {"search", "export", "marketing", "cache", "secondary_identifier", "user_export", "profile"}:
            op, state = "REPORT_REMAINING_RECORD", "PRESENT"
            remop, remstate, verop, vers = "DELETE_RECORD", "ABSENT", "VERIFY_RECORD_ABSENT", "ABSENT"
        elif typ in {"support", "support_attachment"}:
            if typ == "support_attachment" or "belongs only to" in txt:
                op, state = "REPORT_REMAINING_RECORD", "PRESENT"
                remop, remstate, verop, vers = "DELETE_RECORD", "ABSENT", "VERIFY_RECORD_ABSENT", "ABSENT"
            else:
                op, state = "REPORT_EXPOSED_PII", "PRESENT"
                remop, remstate, verop, vers = "REDACT_RECORD", "REDACTED", "VERIFY_RECORD_REDACTED", "REDACTED"
        elif typ == "analytics":
            op, state = "REPORT_EXPOSED_PII", "PRESENT"
            remop, remstate, verop, vers = "ANONYMIZE_RECORD", "ANONYMIZED", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
        elif typ == "data_flow" or typ == "integration":
            disabled = any(v in txt for v in ("enabled=false", "enabled\": false", "enabled': false", "enabled = 0", "disabled"))
            if disabled:
                continue
            op, state = "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"
            remop, remstate, verop, vers = "DISABLE_DATA_FLOW", "DISABLED", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
        elif typ == "backup":
            blocked = any(v in txt for v in ("restore_allowed=0", "restore_allowed\": 0", "restore_allowed': 0", "restore_allowed = 0", "restore_allowed=false"))
            if blocked:
                continue
            op, state = "REPORT_RESTORE_RISK", "ACTIVE"
            remop, remstate, verop, vers = "BLOCK_RESTORE", "BLOCKED", "VERIFY_RESTORE_BLOCKED", "BLOCKED"
        elif typ == "tombstone":
            if any(k in txt for k in ('"email": null', '"phone": null', '"name": null')):
                continue
            op, state = "REPORT_EXPOSED_PII", "PRESENT"
            remop, remstate, verop, vers = "REDACT_RECORD", "REDACTED", "VERIFY_RECORD_REDACTED", "REDACTED"
        else:
            continue
        findings.append({
            "step_no": 0, "phase": "FINDING", "system_id": system,
            "resource_id": rid, "operation": op, "state": state,
            "evidence_id": ev["id"], "_rem": (remop, remstate, verop, vers)
        })
    # The account identifier is the best evidence-backed account resource, if found.
    account_candidates = [s["resource_id"] for s in findings if s["resource_id"].startswith("account_")]
    if not account_candidates:
        # Find a relevant account resource ID from any exact identifier line in evidence.
        for key in match_values:
            for rid, entries in evidence_index.get(key.lower(), {}).items():
                if rid.startswith("account_"):
                    for entry in entries:
                        if not audit_at or not entry[0]["time"] or entry[0]["time"] <= audit_at:
                            account_candidates.append(rid)
    account_id = sorted(set(account_candidates))[0] if account_candidates else ""
    # A retained security audit is only included when directly associated with the user.
    security = []
    for rid, (ev, snippet, rec) in current.items():
        if rid.startswith("audit_record_"):
            security.append((rid, ev))
    # Add a verification for each finding's intended post-remediation state.
    remediation = []
    verifications = []
    for f in findings:
        remop, remstate, verop, vers = f.pop("_rem")
        remediation.append({
            "step_no": 0, "phase": "REMEDIATION", "system_id": f["system_id"],
            "resource_id": f["resource_id"], "operation": remop,
            "state": remstate, "evidence_id": ""
        })
        verifications.append({
            "step_no": 0, "phase": "VERIFICATION", "system_id": f["system_id"],
            "resource_id": f["resource_id"], "operation": verop,
            "state": vers, "evidence_id": ""
        })
    if account_id and not any(s["resource_id"] == account_id and s["phase"] == "FINDING" for s in findings):
        verifications.append({
            "step_no": 0, "phase": "VERIFICATION", "system_id": "account_service",
            "resource_id": account_id, "operation": "VERIFY_RECORD_ABSENT",
            "state": "ABSENT", "evidence_id": ""
        })
    for rid, ev in security[:1]:
        verifications.append({
            "step_no": 0, "phase": "VERIFICATION", "system_id": "security_service",
            "resource_id": rid, "operation": "VERIFY_RECORD_PRESENT",
            "state": "PRESENT", "evidence_id": ""
        })
    if findings:
        steps = findings + remediation + verifications
        status = "INCOMPLETE"
    else:
        # Do not claim completion without a direct evidence-backed account absence.
        absent = None
        for key in match_values:
            for rid, entries in evidence_index.get(key.lower(), {}).items():
                if not rid.startswith("account_"):
                    continue
                for entry in entries:
                    ev, snippet, _rec = entry
                    if audit_at and ev["time"] and ev["time"] > audit_at:
                        continue
                    if re.search(r"(rows=0|http_status=404|status_code.?[:=].?404|profile.?[:=].?null)", snippet, re.I):
                        absent = (rid, ev["id"])
        if absent:
            steps = [{
                "step_no": 1, "phase": "VERIFICATION", "system_id": "account_service",
                "resource_id": absent[0], "operation": "VERIFY_RECORD_ABSENT",
                "state": "ABSENT", "evidence_id": absent[1]
            }]
            status = "COMPLETE"
        else:
            steps = []
            status = "NOT_APPLICABLE"
    steps.sort(key=lambda s: (
        PHASE_ORDER.get(s["phase"], 9), OP_ORDER.get(s["operation"], 9),
        s["system_id"], s["resource_id"]
    ))
    for i, step in enumerate(steps, 1):
        step["step_no"] = i
    # Output keys are intentionally stable and compact.
    clean = [{k: s[k] for k in ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")} for s in steps]
    return status, clean

def main():
    requests = read_csv(DATA / "deletion_requests.csv")
    identities = read_csv(DATA / "user_identities.csv")
    audit = read_csv(DATA / "user_audit_log.csv")
    evidence = file_evidence()
    evidence_index = build_evidence_index(evidence)
    rows = []
    for case in requests:
        status, steps = build_case(case, evidence, identities, audit, evidence_index)
        rows.append({
            "case_id": case["case_id"],
            "deletion_status": status,
            "steps_json": json.dumps(steps, separators=(",", ":"), ensure_ascii=False)
        })
    rows.sort(key=lambda r: r["case_id"])
    with OUT.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows to {OUT}")
    print("Statuses:", {s: sum(r["deletion_status"] == s for r in rows) for s in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")})

if __name__ == "__main__":
    main()
