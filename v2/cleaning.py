import pandas as pd
from pathlib import Path

# Read both CSVs
url_crux ='https://drive.google.com/file/d/1kqZqGfmuFI_CX5K2gEWs33bAO2P0RDv6/view?usp=sharing'
file_id = url_crux.split('/')[-2]
dwn_url_crux='https://drive.google.com/uc?id=' + file_id
df_crux = pd.read_csv(dwn_url_crux)

url_tranco ='https://drive.google.com/file/d/1rPL3TuIqre332JZH2V2A-rW4I3d1VgrH/view?usp=sharing'
file_id = url_tranco.split('/')[-2]
dwn_url_tranco='https://drive.google.com/uc?id=' + file_id
df_tranco = pd.read_csv(dwn_url_tranco)

# Output path
OUTPUT = Path(__file__).parent / "data" / "domains_br.txt"

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
