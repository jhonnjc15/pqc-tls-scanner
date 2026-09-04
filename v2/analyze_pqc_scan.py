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

# Create 'protocol' column if missing
if 'protocol' not in df.columns:
    df['protocol'] = 'https'
    df.loc[df['error'].notna() & (df['error'] != ''), 'protocol'] = 'failed'
    df.loc[df['tls_version'].isna(), 'protocol'] = 'http'

# Protocol counts
protocol_counts = df['protocol'].value_counts().reset_index()
protocol_counts.columns = ['Protocol', 'Count']
order = ['failed', 'http', 'https']
protocol_counts = protocol_counts.set_index('Protocol').reindex(order, fill_value=0).reset_index()
protocol_counts.columns = ['Protocol', 'Count']

# Successful HTTPS
success = df[df['protocol'] == 'https']

# TLS version
tls_counts = success['tls_version'].value_counts().reset_index()
tls_counts.columns = ['TLS Version', 'Count']

# PQC vs Classic (only those with kex_group)
success_valid = success[success['kex_group'].notna()]
success_valid['pqc'] = success_valid['kex_group'].apply(lambda x: 'MLKEM' in str(x) if pd.notna(x) else False)
pqc_count = success_valid['pqc'].sum()
classic_count = len(success_valid) - pqc_count
pqc_data = pd.DataFrame({
    'Category': ['PQC (ML-KEM)', 'Classic'],
    'Count': [pqc_count, classic_count]
})

# ------------------------------------------------------------
# Cipher Suites (top 10 para no saturar)
# ------------------------------------------------------------
cipher_counts = success_valid['cipher'].value_counts().reset_index()
cipher_counts.columns = ['Cipher Suite', 'Count']
# Si hay más de 10, nos quedamos con los 10 principales
cipher_counts = cipher_counts.head(10)

# ------------------------------------------------------------
# Signature Algorithms
# ------------------------------------------------------------
sig_counts = success_valid['signature_algorithm'].value_counts().reset_index()
sig_counts.columns = ['Signature Algorithm', 'Count']
# Opcional: también top 10
sig_counts = sig_counts.head(10)



# Plot settings
sns.set_style('whitegrid')
plt.rcParams['figure.figsize'] = (8, 5)
output_dir = os.path.join('v2', 'graphics')
os.makedirs(output_dir, exist_ok=True)

# Helper to add labels (number and percentage in one line)
def add_labels(ax, data, col='Count'):
    total = data[col].sum()
    if total == 0:
        return
    max_val = data[col].max()
    for i, (idx, row) in enumerate(data.iterrows()):
        val = row[col]
        pct = (val / total) * 100
        ax.text(i, val + max_val*0.02, f'{val} ({pct:.1f}%)',
                ha='center', va='bottom', fontsize=10, fontweight='bold')
    ax.set_ylim(0, max_val * 1.2 if max_val > 0 else 1)

# Graph 1: Protocol
fig1, ax1 = plt.subplots()
sns.barplot(data=protocol_counts, x='Protocol', y='Count',
            hue='Protocol', palette=['#e74c3c', '#f39c12', '#2ecc71'], legend=False, ax=ax1)
ax1.set_title('Protocol distribution', fontsize=12)
ax1.set_ylabel('Number of domains')
ax1.set_xlabel('Protocol')
add_labels(ax1, protocol_counts)
plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'protocol_distribution.png'), dpi=150)
plt.close()

# Graph 2: TLS version
fig2, ax2 = plt.subplots()
sns.barplot(data=tls_counts, x='TLS Version', y='Count',
            hue='TLS Version', palette='viridis', legend=False, ax=ax2)
ax2.set_title('TLS version distribution (HTTPS)', fontsize=12)
ax2.set_ylabel('Number of domains')
ax2.set_xlabel('TLS version')
add_labels(ax2, tls_counts)
plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'tls_version.png'), dpi=150)
plt.close()

# Graph 3: PQC vs Classic
fig3, ax3 = plt.subplots()
sns.barplot(data=pqc_data, x='Category', y='Count',
            hue='Category', palette=['#2ecc71', '#e74c3c'], legend=False, ax=ax3)
ax3.set_title('Key exchange: PQC vs Classic (HTTPS)', fontsize=12)
ax3.set_ylabel('Number of domains')
ax3.set_xlabel('Key exchange type')
add_labels(ax3, pqc_data)
plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'pqc_vs_classic.png'), dpi=150)
plt.close()



# ------------------------------------------------------------
# Gráfico 4: Cipher Suites
# ------------------------------------------------------------
fig4, ax4 = plt.subplots()
sns.barplot(data=cipher_counts, x='Cipher Suite', y='Count',
            hue='Cipher Suite', palette='plasma', legend=False, ax=ax4)
ax4.set_title('Top 10 Cipher Suites negotiated (HTTPS)', fontsize=12)
ax4.set_ylabel('Number of domains')
ax4.set_xlabel('Cipher Suite')
# Rotar etiquetas para que no se solapen
ax4.set_xticklabels(ax4.get_xticklabels(), rotation=45, ha='right')
add_labels(ax4, cipher_counts)
plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'cipher_suites.png'), dpi=150)
plt.close()

# ------------------------------------------------------------
# Gráfico 5: Signature Algorithms
# ------------------------------------------------------------
fig5, ax5 = plt.subplots()
sns.barplot(data=sig_counts, x='Signature Algorithm', y='Count',
            hue='Signature Algorithm', palette='coolwarm', legend=False, ax=ax5)
ax5.set_title('Signature Algorithms used (HTTPS)', fontsize=12)
ax5.set_ylabel('Number of domains')
ax5.set_xlabel('Signature Algorithm')
ax5.set_xticklabels(ax5.get_xticklabels(), rotation=45, ha='right')
add_labels(ax5, sig_counts)
plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'signature_algorithms.png'), dpi=150)
plt.close()




# Print values
print("Graphs generated -> v2/graphics/")
print("Protocol distribution:")
for _, row in protocol_counts.iterrows():
    print(f"  {row['Protocol']}: {row['Count']} ({row['Count']/protocol_counts['Count'].sum()*100:.1f}%)")
print("TLS version distribution:")
for _, row in tls_counts.iterrows():
    print(f"  {row['TLS Version']}: {row['Count']} ({row['Count']/tls_counts['Count'].sum()*100:.1f}%)")
print("PQC vs Classic (successful handshakes):")
for _, row in pqc_data.iterrows():
    print(f"  {row['Category']}: {row['Count']} ({row['Count']/pqc_data['Count'].sum()*100:.1f}%)")
print("Cipher Suites (top 10):")
for _, row in cipher_counts.iterrows():
    print(f"  {row['Cipher Suite']}: {row['Count']} ({row['Count']/cipher_counts['Count'].sum()*100:.1f}%)")

print("Signature Algorithms:")
for _, row in sig_counts.iterrows():
    print(f"  {row['Signature Algorithm']}: {row['Count']} ({row['Count']/sig_counts['Count'].sum()*100:.1f}%)")