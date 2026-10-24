
import pandas as pd
import os

files = [
    "dataset/deletion_requests.csv",
    "dataset/deletion_rules.csv",
    "dataset/evidence_files.csv",
    "dataset/user_identities.csv",
    "dataset/user_audit_log.csv",
    "dataset/system_activity.csv",
    "dataset/sample_output.csv",
]

for file in files:
    df = pd.read_csv(file)

    print("\n" + "=" * 60)
    print("FILE:", file)
    print("SHAPE:", df.shape)
    print("COLUMNS:", list(df.columns))
    print(df.head(3).to_string(index=False))

evidence_count = sum(
    len(files)
    for _, _, files in os.walk("dataset/evidence")
)

print("\nEvidence file count:", evidence_count)

sample = pd.read_csv("dataset/sample_output.csv")
print("\nSample status counts:")
print(sample["deletion_status"].value_counts())

requests = pd.read_csv("dataset/deletion_requests.csv")
print("\nFull request count:", len(requests))
