#!/usr/bin/env python3
"""
Generate thesis charts for Experiment 1: LLM Model Comparison
Creates matplotlib visualizations comparing 5 models on malware detection task.
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from pathlib import Path

# Output directory for thesis images
OUTPUT_DIR = Path(__file__).parent.parent / "thesis-report/src/images/chapter4"

# Model data from stress test reports
MODELS = {
    "gpt-oss-120b": {
        "display_name": "GPT-OSS-120B",
        "accuracy": 83.50,
        "precision": 78.15,
        "recall": 93.00,
        "f1": 84.93,
        "cost": 0.358,
        "tokens_prompt": 1.39,  # In millions
        "tokens_reasoning": 0,
        "tokens_completion": 0.255,
        "time_minutes": 91.72,
        "tp": 93, "fp": 26, "tn": 74, "fn": 7
    },
    "gpt-5-mini": {
        "display_name": "GPT-5-Mini",
        "accuracy": 83.76,
        "precision": 78.33,
        "recall": 94.00,
        "f1": 85.45,
        "cost": 1.86,
        "tokens_prompt": 1.69,
        "tokens_reasoning": 0.386,
        "tokens_completion": 0.721,
        "time_minutes": 260.78,
        "tp": 94, "fp": 26, "tn": 71, "fn": 6
    },
    "deepseek-v3-2": {
        "display_name": "DeepSeek-V3.2",
        "accuracy": 78.89,
        "precision": 72.09,
        "recall": 93.94,
        "f1": 81.58,
        "cost": 2.77,
        "tokens_prompt": 5.72,
        "tokens_reasoning": 2.56,
        "tokens_completion": 3.29,
        "time_minutes": 760.65,
        "tp": 93, "fp": 36, "tn": 64, "fn": 6
    },
    "gemini-3-flash": {
        "display_name": "Gemini-3-Flash",
        "accuracy": 72.00,
        "precision": 64.47,
        "recall": 98.00,
        "f1": 77.78,
        "cost": 1.54,
        "tokens_prompt": 2.2,
        "tokens_reasoning": 0,
        "tokens_completion": 0.145,
        "time_minutes": 88.62,
        "tp": 98, "fp": 54, "tn": 46, "fn": 2
    },
    "llama-4-maverick": {
        "display_name": "Llama-4-Maverick",
        "accuracy": 76.50,
        "precision": 68.79,
        "recall": 97.00,
        "f1": 80.50,
        "cost": 0.487,
        "tokens_prompt": 2.13,
        "tokens_reasoning": 0,
        "tokens_completion": 0.155,
        "time_minutes": 105.65,
        "tp": 97, "fp": 44, "tn": 56, "fn": 3
    }
}

# Color palette
COLORS = {
    "gpt-oss-120b": "#4CAF50",      # Green
    "gpt-5-mini": "#2196F3",         # Blue
    "deepseek-v3-2": "#9C27B0",      # Purple
    "gemini-3-flash": "#FF9800",     # Orange
    "llama-4-maverick": "#F44336"    # Red
}

plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams['font.family'] = 'DejaVu Sans'
plt.rcParams['font.size'] = 11
plt.rcParams['axes.labelsize'] = 12
plt.rcParams['axes.titlesize'] = 14


def create_accuracy_comparison():
    """Create bar chart comparing accuracy metrics across models."""
    fig, ax = plt.subplots(figsize=(12, 6))
    
    models = list(MODELS.keys())
    display_names = [MODELS[m]["display_name"] for m in models]
    x = np.arange(len(models))
    width = 0.2
    
    metrics = ['accuracy', 'precision', 'recall', 'f1']
    metric_labels = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    metric_colors = ['#2196F3', '#4CAF50', '#FF9800', '#9C27B0']
    
    for i, (metric, label, color) in enumerate(zip(metrics, metric_labels, metric_colors)):
        values = [MODELS[m][metric] for m in models]
        bars = ax.bar(x + i * width, values, width, label=label, color=color, alpha=0.85)
        
        # Add value labels on bars
        for bar, val in zip(bars, values):
            ax.annotate(f'{val:.1f}%',
                       xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
                       xytext=(0, 3), textcoords="offset points",
                       ha='center', va='bottom', fontsize=8, rotation=45)
    
    ax.set_ylabel('Percentage (%)')
    ax.set_title('Model Performance Comparison on Malware Detection (200 Commits)')
    ax.set_xticks(x + width * 1.5)
    ax.set_xticklabels(display_names, rotation=15, ha='right')
    ax.legend(loc='upper right')
    ax.set_ylim(0, 110)
    ax.axhline(y=80, color='gray', linestyle='--', alpha=0.5, label='80% threshold')
    
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "exp1_accuracy_comparison.png", dpi=150, bbox_inches='tight')
    plt.close()
    print(f"✓ Created exp1_accuracy_comparison.png")


def create_cost_vs_accuracy():
    """Create scatter plot of cost vs accuracy."""
    fig, ax = plt.subplots(figsize=(10, 7))
    
    for model_id, data in MODELS.items():
        size = data['tokens_prompt'] * 100 + 50  # Size based on token usage
        ax.scatter(data['cost'], data['accuracy'], 
                  s=size, c=COLORS[model_id], alpha=0.7, 
                  edgecolors='black', linewidth=1)
        
        # Add model label
        offset_x = 0.05 if data['cost'] < 2 else -0.3
        offset_y = 1 if data['accuracy'] > 77 else -2
        ax.annotate(data['display_name'], 
                   (data['cost'], data['accuracy']),
                   xytext=(offset_x, offset_y), textcoords='offset points',
                   fontsize=10, fontweight='bold')
    
    ax.set_xlabel('Cost (USD) for 200 Commits')
    ax.set_ylabel('Accuracy (%)')
    ax.set_title('Cost-Efficiency Analysis: Cost vs Accuracy')
    
    # Add efficiency frontier annotation
    ax.annotate('Best Cost-Efficiency', 
               xy=(0.358, 83.50), xytext=(0.8, 78),
               arrowprops=dict(arrowstyle='->', color='green'),
               fontsize=10, color='green')
    
    ax.set_xlim(-0.1, 3.2)
    ax.set_ylim(68, 88)
    ax.grid(True, alpha=0.3)
    
    # Add size legend
    sizes = [100, 300, 600]
    labels = ['~1M tokens', '~3M tokens', '~6M tokens']
    legend_elements = [plt.scatter([], [], s=s, c='gray', alpha=0.5, label=l) 
                      for s, l in zip(sizes, labels)]
    ax.legend(handles=legend_elements, title='Token Usage', loc='lower right')
    
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "exp1_cost_vs_accuracy.png", dpi=150, bbox_inches='tight')
    plt.close()
    print(f"✓ Created exp1_cost_vs_accuracy.png")


def create_token_usage():
    """Create stacked bar chart of token usage."""
    fig, ax = plt.subplots(figsize=(10, 6))
    
    models = list(MODELS.keys())
    display_names = [MODELS[m]["display_name"] for m in models]
    x = np.arange(len(models))
    width = 0.6
    
    prompt_tokens = [MODELS[m]["tokens_prompt"] for m in models]
    reasoning_tokens = [MODELS[m]["tokens_reasoning"] for m in models]
    completion_tokens = [MODELS[m]["tokens_completion"] for m in models]
    
    bars1 = ax.bar(x, prompt_tokens, width, label='Prompt Tokens', color='#2196F3')
    bars2 = ax.bar(x, reasoning_tokens, width, bottom=prompt_tokens, 
                   label='Reasoning Tokens', color='#9C27B0')
    bars3 = ax.bar(x, completion_tokens, width, 
                   bottom=[p + r for p, r in zip(prompt_tokens, reasoning_tokens)],
                   label='Completion Tokens', color='#4CAF50')
    
    # Add total labels
    totals = [p + r + c for p, r, c in zip(prompt_tokens, reasoning_tokens, completion_tokens)]
    for i, (bar, total) in enumerate(zip(bars3, totals)):
        ax.annotate(f'{total:.2f}M',
                   xy=(bar.get_x() + bar.get_width() / 2, 
                       prompt_tokens[i] + reasoning_tokens[i] + completion_tokens[i]),
                   xytext=(0, 3), textcoords="offset points",
                   ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    ax.set_ylabel('Tokens (Millions)')
    ax.set_title('Token Usage Breakdown by Model')
    ax.set_xticks(x)
    ax.set_xticklabels(display_names, rotation=15, ha='right')
    ax.legend(loc='upper right')
    
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "exp1_token_usage.png", dpi=150, bbox_inches='tight')
    plt.close()
    print(f"✓ Created exp1_token_usage.png")


def create_time_comparison():
    """Create bar chart comparing processing time."""
    fig, ax = plt.subplots(figsize=(10, 6))
    
    models = list(MODELS.keys())
    display_names = [MODELS[m]["display_name"] for m in models]
    times = [MODELS[m]["time_minutes"] for m in models]
    colors = [COLORS[m] for m in models]
    
    bars = ax.barh(display_names, times, color=colors, alpha=0.8, edgecolor='black')
    
    # Add time labels
    for bar, time in zip(bars, times):
        hours = int(time // 60)
        mins = int(time % 60)
        time_str = f"{hours}h {mins}m" if hours > 0 else f"{mins}m"
        ax.annotate(time_str,
                   xy=(bar.get_width(), bar.get_y() + bar.get_height() / 2),
                   xytext=(5, 0), textcoords="offset points",
                   ha='left', va='center', fontsize=10, fontweight='bold')
    
    ax.set_xlabel('Total Processing Time (Minutes)')
    ax.set_title('Processing Time for 200 Commits')
    ax.set_xlim(0, max(times) * 1.15)
    
    # Add average time per commit annotation
    avg_times = [t / 200 for t in times]
    ax2 = ax.twiny()
    ax2.set_xlim(0, max(times) * 1.15 / 200)
    ax2.set_xlabel('Average Time per Commit (Minutes)')
    
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "exp1_time_comparison.png", dpi=150, bbox_inches='tight')
    plt.close()
    print(f"✓ Created exp1_time_comparison.png")


def create_confusion_matrix_heatmap():
    """Create heatmap showing TP/TN/FP/FN for each model."""
    fig, axes = plt.subplots(1, 5, figsize=(16, 4))
    
    models = list(MODELS.keys())
    
    for ax, model_id in zip(axes, models):
        data = MODELS[model_id]
        matrix = np.array([
            [data['tn'], data['fp']],
            [data['fn'], data['tp']]
        ])
        
        im = ax.imshow(matrix, cmap='Blues', aspect='auto')
        
        # Add text annotations
        for i in range(2):
            for j in range(2):
                color = 'white' if matrix[i, j] > 50 else 'black'
                ax.text(j, i, str(matrix[i, j]), ha='center', va='center', 
                       fontsize=14, fontweight='bold', color=color)
        
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(['Pred: Benign', 'Pred: Malware'], fontsize=9)
        ax.set_yticklabels(['True: Benign', 'True: Malware'], fontsize=9)
        ax.set_title(data['display_name'], fontsize=11, fontweight='bold')
    
    plt.suptitle('Confusion Matrices by Model (200 Commits: 100 Malware + 100 Benign)', 
                 fontsize=13, y=1.02)
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "exp1_confusion_matrix.png", dpi=150, bbox_inches='tight')
    plt.close()
    print(f"✓ Created exp1_confusion_matrix.png")


def main():
    """Generate all thesis charts."""
    print(f"Output directory: {OUTPUT_DIR}")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    print("\nGenerating Experiment 1 charts...")
    create_accuracy_comparison()
    create_cost_vs_accuracy()
    create_token_usage()
    create_time_comparison()
    create_confusion_matrix_heatmap()
    
    print(f"\n✅ All charts generated successfully in {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
