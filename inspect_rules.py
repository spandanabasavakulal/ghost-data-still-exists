
import pandas as pd
import os
import json

print("========== DELETION RULES ==========")
rules = pd.read_csv("dataset/deletion_rules.csv")
print(rules.to_string(index=False))

print("\n========== EVIDENCE FILE TYPES ==========")
manifest = pd.read_csv("dataset/evidence_files.csv")

for _, row in manifest.iterrows():
    path = os.path.join("dataset", row["file_path"])
    ext = os.path.splitext(path)[1].lower()
    print(f'{row["file_id"]:15} {ext:8} {row["file_path"]}')

print("\n========== EVIDENCE EXAMPLES ==========")
for _, row in manifest.head(8).iterrows():
    path = os.path.join("dataset", row["file_path"])
    print(f"\n--- {row['file_id']} | {row['file_path']} ---")

    if not os.path.exists(path):
        print("FILE NOT FOUND")
        continue

    try:
        with open(path, "r", encoding="utf-8") as f:
            print(f.read(1500))
    except Exception as e:
        print("Cannot read as text:", e)
