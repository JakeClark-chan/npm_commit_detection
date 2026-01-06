#!/usr/bin/env python3
"""
Generate visualizations for Experiment 3: Real-world Malware Detection
Comparing Llama-4-Maverick vs GPT-OSS-120B on real malware repositories
"""

import matplotlib.pyplot as plt
import numpy as np
import os
from pathlib import Path

# Create output directory - use absolute path relative to this script
SCRIPT_DIR = Path(__file__).parent.resolve()
OUTPUT_DIR = SCRIPT_DIR.parent / "thesis-report" / "src" / "images" / "chapter4"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Data extracted from reports
models = ["Llama-4-Maverick", "GPT-OSS-120B"]

# Statistics from reports
data = {
    "Llama-4-Maverick": {
        "repos": 38,
        "total_commits": 1526,
        "malware_found": 136,
        "benign_found": 1390,
        "static_time_total": 2598.36,
        "verification_time_total": 485.27,
        "total_time": 3102.31,
    },
    "GPT-OSS-120B": {
        "repos": 39,
        "total_commits": 1528,
        "malware_found": 67,
        "benign_found": 1461,
        "static_time_total": 1757.95,
        "verification_time_total": 266.81,
        "total_time": 2028.67,
    }
}

# Set style
plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams['figure.dpi'] = 150
plt.rcParams['font.size'] = 11


def plot_malware_detection_comparison():
    """Bar chart comparing malware/benign detection between models"""
    fig, ax = plt.subplots(figsize=(10, 6))
    
    x = np.arange(len(models))
    width = 0.35
    
    malware_counts = [data[m]["malware_found"] for m in models]
    benign_counts = [data[m]["benign_found"] for m in models]
    
    bars1 = ax.bar(x - width/2, malware_counts, width, label='Malware Detected', color='#e74c3c')
    bars2 = ax.bar(x + width/2, benign_counts, width, label='Benign', color='#2ecc71')
    
    ax.set_xlabel('Model', fontsize=12)
    ax.set_ylabel('Number of Commits', fontsize=12)
    ax.set_title('Malware vs Benign Classification by Model', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(models)
    ax.legend()
    
    # Add value labels on bars
    for bar in bars1:
        height = bar.get_height()
        ax.annotate(f'{int(height)}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points",
                    ha='center', va='bottom', fontweight='bold')
    for bar in bars2:
        height = bar.get_height()
        ax.annotate(f'{int(height)}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points",
                    ha='center', va='bottom', fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(f"{OUTPUT_DIR}/exp3_malware_detection_comparison.png", bbox_inches='tight')
    plt.close()
    print(f"Saved: {OUTPUT_DIR}/exp3_malware_detection_comparison.png")


def plot_detection_rate():
    """Pie charts showing detection rates for each model"""
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    
    colors = ['#e74c3c', '#2ecc71']
    
    for idx, model in enumerate(models):
        malware = data[model]["malware_found"]
        benign = data[model]["benign_found"]
        total = malware + benign
        
        sizes = [malware, benign]
        labels = [f'Malware\n({malware}, {malware/total*100:.1f}%)', 
                  f'Benign\n({benign}, {benign/total*100:.1f}%)']
        
        axes[idx].pie(sizes, labels=labels, colors=colors, autopct='',
                      startangle=90, explode=(0.05, 0))
        axes[idx].set_title(model, fontsize=13, fontweight='bold')
    
    plt.suptitle('Commit Classification Distribution', fontsize=14, fontweight='bold', y=1.02)
    plt.tight_layout()
    plt.savefig(f"{OUTPUT_DIR}/exp3_detection_rate_comparison.png", bbox_inches='tight')
    plt.close()
    print(f"Saved: {OUTPUT_DIR}/exp3_detection_rate_comparison.png")


def plot_execution_time():
    """Bar chart comparing execution times"""
    fig, ax = plt.subplots(figsize=(10, 6))
    
    x = np.arange(len(models))
    width = 0.25
    
    static_times = [data[m]["static_time_total"] / 60 for m in models]  # Convert to minutes
    verify_times = [data[m]["verification_time_total"] / 60 for m in models]
    total_times = [data[m]["total_time"] / 60 for m in models]
    
    bars1 = ax.bar(x - width, static_times, width, label='Static Analysis', color='#3498db')
    bars2 = ax.bar(x, verify_times, width, label='LLM Verification', color='#9b59b6')
    bars3 = ax.bar(x + width, total_times, width, label='Total', color='#1abc9c')
    
    ax.set_xlabel('Model', fontsize=12)
    ax.set_ylabel('Time (minutes)', fontsize=12)
    ax.set_title('Execution Time Comparison', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(models)
    ax.legend()
    
    # Add value labels
    for bars in [bars1, bars2, bars3]:
        for bar in bars:
            height = bar.get_height()
            ax.annotate(f'{height:.1f}m',
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3), textcoords="offset points",
                        ha='center', va='bottom', fontsize=9)
    
    plt.tight_layout()
    plt.savefig(f"{OUTPUT_DIR}/exp3_execution_time.png", bbox_inches='tight')
    plt.close()
    print(f"Saved: {OUTPUT_DIR}/exp3_execution_time.png")


def plot_summary_metrics():
    """Summary metrics comparison"""
    fig, axes = plt.subplots(1, 3, figsize=(14, 5))
    
    # Plot 1: Total commits analyzed
    commits = [data[m]["total_commits"] for m in models]
    axes[0].bar(models, commits, color=['#3498db', '#e74c3c'])
    axes[0].set_title('Total Commits Analyzed', fontsize=12, fontweight='bold')
    axes[0].set_ylabel('Commits')
    for i, v in enumerate(commits):
        axes[0].text(i, v + 20, str(v), ha='center', fontweight='bold')
    
    # Plot 2: Malware detection rate  
    rates = [data[m]["malware_found"] / data[m]["total_commits"] * 100 for m in models]
    axes[1].bar(models, rates, color=['#3498db', '#e74c3c'])
    axes[1].set_title('Malware Detection Rate (%)', fontsize=12, fontweight='bold')
    axes[1].set_ylabel('Percentage (%)')
    for i, v in enumerate(rates):
        axes[1].text(i, v + 0.3, f'{v:.2f}%', ha='center', fontweight='bold')
    
    # Plot 3: Processing speed (commits/minute)
    speeds = [data[m]["total_commits"] / (data[m]["total_time"] / 60) for m in models]
    axes[2].bar(models, speeds, color=['#3498db', '#e74c3c'])
    axes[2].set_title('Processing Speed (commits/min)', fontsize=12, fontweight='bold')
    axes[2].set_ylabel('Commits per minute')
    for i, v in enumerate(speeds):
        axes[2].text(i, v + 0.5, f'{v:.1f}', ha='center', fontweight='bold')
    
    plt.suptitle('Experiment 3: Real-World Malware Detection Summary', fontsize=14, fontweight='bold', y=1.02)
    plt.tight_layout()
    plt.savefig(f"{OUTPUT_DIR}/exp3_summary_metrics.png", bbox_inches='tight')
    plt.close()
    print(f"Saved: {OUTPUT_DIR}/exp3_summary_metrics.png")


if __name__ == "__main__":
    print("Generating Experiment 3 visualizations...")
    plot_malware_detection_comparison()
    plot_detection_rate()
    plot_execution_time()
    plot_summary_metrics()
    print("\nAll visualizations generated successfully!")
