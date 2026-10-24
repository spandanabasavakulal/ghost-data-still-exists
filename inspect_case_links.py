
import os
import re
import pandas as pd

requests = pd.read_csv("dataset/sample_deletion_requests.csv")
identities = pd.read_csv("dataset/user_identities.csv").fillna("")
history = pd.read_csv("dataset/user_audit_log.csv").fillna("")
manifest = pd.read_csv("dataset/evidence_files.csv").fillna("")
activity = pd.read_csv("dataset/system_activity.csv").fillna("")

# Inspect the first 12 sample cases.
for _, case in requests.head(12).iterrows():
    email = str(case["email"]).strip().lower()

    current = identities[
        identities["email"].str.lower() == email
    ]

    user_ids = set(current["user_id"].astype(str))
    aliases = {email}

    # Recover historical identity values.
    if user_ids:
        user_history = history[
            history["user_id"].astype(str).isin(user_ids)
        ]

        for _, row in user_history.iterrows():
            if str(row["field_name"]).lower() == "email":
                aliases.add(str(row["old_value"]).strip().lower())
                aliases.add(str(row["new_value"]).strip().lower())

    aliases.discard("")

    print("\n" + "=" * 70)
    print("CASE:", case["case_id"], "| EMAIL:", email)
    print("USER IDS:", sorted(user_ids))
    print("EMAIL ALIASES:", sorted(aliases))

    # Match operational activity.
    activity_text = activity.astype(str).agg(" ".join, axis=1)
    activity_hits = activity[
        activity_text.str.lower().apply(
            lambda text: any(alias in text for alias in aliases)
            or any(uid in text for uid in user_ids)
        )
    ]

    print("\nACTIVITY MATCHES:", len(activity_hits))
    print(activity_hits.head(8).to_string(index=False))

    # Search readable evidence files.
    print("\nEVIDENCE MATCHES:")
    count = 0

    for _, item in manifest.iterrows():
        path = os.path.join("dataset", str(item["file_path"]))

        if not os.path.isfile(path):
            continue

        ext = os.path.splitext(path)[1].lower()
        if ext not in {".txt", ".log", ".json", ".sql", ".csv", ".md"}:
            continue

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError:
            continue

        lines = content.splitlines()
        matches = [
            (i + 1, line.strip()[:250])
            for i, line in enumerate(lines)
            if any(alias in line.lower() for alias in aliases)
            or any(uid in line for uid in user_ids)
        ]

        if matches:
            print(
                item["file_id"],
                item["file_path"],
                "MATCHES:",
                len(matches)
            )

            for line_no, text in matches[:2]:
                print(f"  Line {line_no}: {text}")

            count += 1
            if count >= 8:
                print("  ...additional matching files omitted")
                break
