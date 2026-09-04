import sys
import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

if len(sys.argv) < 2:
    print("Usage: python script.py <csv_file>")
    sys.exit(1)

csv_file = sys.argv[1]
df = pd.read_csv(csv_file)
df.columns = df.columns.str.strip()

# Keep only successful TLS handshakes
success = df[df['tls_version'].notna() & df['kex_group'].notna()]

# Identify PQC groups (contain 'MLKEM')
def is_pqc(group):
    return 'MLKEM' in str(group) if pd.notna(group) else False

success['pqc'] = success['kex_group'].apply(is_pqc)
pqc_count = success['pqc'].sum()
classic_count = len(success) - pqc_count

# Data for PQC vs Classic
pqc_data = pd.DataFrame({
    'Category': ['PQC (ML-KEM)', 'Classic'],
    'Count': [pqc_count, classic_count]
})

# TLS version distribution
tls_counts = success['tls_version'].value_counts().reset_index()
tls_counts.columns = ['TLS Version', 'Count']

# Plot styling
sns.set_style('whitegrid')
plt.rcParams['figure.figsize'] = (8, 5)

# Output directory inside v2/
output_dir = os.path.join('v2', 'graphics')
os.makedirs(output_dir, exist_ok=True)

#  Graph 1: TLS Version 
plt.figure()
sns.barplot(data=tls_counts, x='TLS Version', y='Count',
            hue='TLS Version', palette='viridis', legend=False)
plt.title('TLS version distribution in successful connections', fontsize=12)
plt.ylabel('Number of domains', fontsize=11)
plt.xlabel('TLS version', fontsize=11)
plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'tls_version.png'), dpi=150)
plt.close()

#  Graph 2: PQC vs Classic 
plt.figure()
sns.barplot(data=pqc_data, x='Category', y='Count',
            hue='Category', palette=['#2ecc71', '#e74c3c'], legend=False)
plt.title('Key exchange negotiation: PQC vs Classic', fontsize=12)
plt.ylabel('Number of domains', fontsize=11)
plt.xlabel('Key exchange type', fontsize=11)
# Add percentage labels on top of bars
total = pqc_data['Count'].sum()
for i, val in enumerate(pqc_data['Count']):
    pct = (val / total) * 100
    plt.text(i, val + 0.5, f'{pct:.1f}%', ha='center', va='bottom', fontsize=10)
plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'pqc_vs_classic.png'), dpi=150)
plt.close()

print("Graphs generated --> 'v2/graphics/'")