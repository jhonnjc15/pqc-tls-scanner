import pandas as pd
from pathlib import Path

# CSV paths
CRUX_CSV = Path.home() / "Downloads" / "bquxjob_7fa696b9_1a03eb5096d.csv"
TRANCO_CSV = Path.home() / "Downloads" / "bq-results-20260826-023653-1787711892583.csv"

# Output path
OUTPUT = Path(__file__).parent / "data" / "domains_br.txt"

# Read both CSVs
df_crux = pd.read_csv(CRUX_CSV)
df_tranco = pd.read_csv(TRANCO_CSV)

# CRUX has bare domains, Tranco has URLs
# Clean Tranco: strip protocol, path, www
df_tranco["origin"] = df_tranco["origin"].str.replace(r"^https?://", "", regex=True)
df_tranco["origin"] = df_tranco["origin"].str.replace(r"/.*$", "", regex=True)
df_tranco["origin"] = df_tranco["origin"].str.replace(r"^www\.", "", regex=True)

# Combine both
df = pd.concat([df_crux, df_tranco], ignore_index=True)

# Keep only .br domains
df = df[df["origin"].str.endswith(".br", na=False)]

# Deduplicate and sort
df = df.drop_duplicates(subset="origin")
df = df.sort_values("origin").reset_index(drop=True)

# Save to file
OUTPUT.parent.mkdir(parents=True, exist_ok=True)
df["origin"].to_csv(OUTPUT, index=False, header=False)

print(f"CRUX: {len(df_crux)} rows")
print(f"Tranco: {len(df_tranco)} rows")
print(f"Combined .br (deduped): {len(df)} domains")
print(f"Saved to: {OUTPUT}")
