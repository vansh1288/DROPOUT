import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import os

def load_metrics(csv_path: str) -> pd.DataFrame:
    return pd.read_csv(csv_path)

def plot_peak_sram_vs_model_size(df: pd.DataFrame, output_path: str):
    fig, ax = plt.subplots(figsize=(8, 6))
    grouped = df.groupby('model_size_bytes')['peak_sram_bytes'].max().reset_index()
    ax.plot(grouped['model_size_bytes'] / 1024, grouped['peak_sram_bytes'] / 1024, 'o-', linewidth=2, markersize=6)
    ax.set_xlabel('Model Size (KB)')
    ax.set_ylabel('Peak SRAM (KB)')
    ax.set_title('Peak SRAM vs Model Size (Streaming Architecture)')
    ax.grid(True, alpha=0.3)
    ax.axhline(y=16.5, color='r', linestyle='--', label='Static Allocation Limit (16.5 KB)')
    ax.legend()
    fig.tight_layout()
    fig.savefig(output_path, format='pdf')
    plt.close(fig)

def plot_latency_vs_dropout(df: pd.DataFrame, output_path: str):
    fig, ax = plt.subplots(figsize=(8, 6))
    grouped = df.groupby('dropout_rate')['round_latency_ms'].agg(['mean', 'std']).reset_index()
    ax.errorbar(grouped['dropout_rate'] * 100, grouped['mean'], yerr=grouped['std'], fmt='o-', capsize=4, linewidth=2)
    ax.set_xlabel('Dropout Rate (%)')
    ax.set_ylabel('Round Latency (ms)')
    ax.set_title('Total Round Latency vs Dropout Rate')
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(output_path, format='pdf')
    plt.close(fig)

def plot_cpu_cycles_breakdown(df: pd.DataFrame, output_path: str):
    fig, ax = plt.subplots(figsize=(8, 6))
    categories = ['keygen_cycles', 'encapsulation_cycles', 'decapsulation_cycles', 'ntt_cycles', 'mask_generation_cycles', 'masking_cycles']
    labels = ['KeyGen', 'Encaps', 'Decaps', 'NTT', 'MaskGen', 'Masking']
    means = [df[c].mean() / 1e6 for c in categories]
    ax.bar(labels, means, color=['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b'])
    ax.set_ylabel('Cycles (Millions)')
    ax.set_title('CPU Cycles Breakdown (ML-KEM-768)')
    ax.grid(True, alpha=0.3, axis='y')
    fig.tight_layout()
    fig.savefig(output_path, format='pdf')
    plt.close(fig)

def main():
    csv_path = 'experiments/results/metrics.csv'
    if not os.path.exists(csv_path):
        return
    df = load_metrics(csv_path)
    os.makedirs('experiments/results/plots', exist_ok=True)
    plot_peak_sram_vs_model_size(df, 'experiments/results/plots/peak_sram_vs_model_size.pdf')
    plot_latency_vs_dropout(df, 'experiments/results/plots/latency_vs_dropout.pdf')
    plot_cpu_cycles_breakdown(df, 'experiments/results/plots/cpu_cycles_breakdown.pdf')

if __name__ == '__main__':
    main()