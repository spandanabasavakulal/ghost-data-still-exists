
import pandas as pd
import json
from collections import Counter

df = pd.read_csv("dataset/sample_output.csv")

for _, row in df.iterrows():
    steps = json.loads(row["steps_json"])
    print(
        row["case_id"],
        row["deletion_status"],
        "steps =", len(steps),
        "operations =", Counter(s["operation"] for s in steps)
    )

print("\n========== INCOMPLETE CASE EXAMPLE ==========")
for _, row in df[df["deletion_status"] == "INCOMPLETE"].head(3).iterrows():
    print("\nCASE:", row["case_id"])
    print(json.dumps(json.loads(row["steps_json"]), indent=2))
