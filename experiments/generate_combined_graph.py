import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
import glob

sys.path.insert(0, '.')


def load_summary_csv(summary_file: str) -> pd.DataFrame:
    """Load the experiment summary CSV"""
    return pd.read_csv(summary_file)


def generate_combined_graph(summary_file: str, output_dir: str = "results/analysis"):
    """Generate a comprehensive graph showing all experiments"""
    os.makedirs(output_dir, exist_ok=True)

    df = load_summary_csv(summary_file)

    # Create figure with multiple subplots
    fig, axes = plt.subplots(2, 2, figsize=(20, 14))
    fig.suptitle('Comprehensive Attack Analysis - All Experiments', fontsize=16, fontweight='bold')

    # 1. Success Rate by Configuration (Top Left)
    ax1 = axes[0, 0]

    # Group by config description and calculate success rate
    config_success = df.groupby('config_description').agg({
        'success': ['sum', 'count']
    }).reset_index()
    config_success.columns = ['config', 'successful', 'total']
    config_success['success_rate'] = (config_success['successful'] / config_success['total']) * 100
    config_success = config_success.sort_values('success_rate', ascending=True)

    # Use shorter labels
    config_success['short_label'] = config_success['config'].apply(lambda x:
        x.replace('Phase 1: ', 'P1: ').replace('Phase 2: ', 'P2: ').replace(' - No protections', '').replace('ARGON2ID - ', '')
    )

    bars = ax1.barh(range(len(config_success)), config_success['success_rate'])
    ax1.set_yticks(range(len(config_success)))
    ax1.set_yticklabels(config_success['short_label'], fontsize=9)
    ax1.set_xlabel('Success Rate (%)', fontsize=11, fontweight='bold')
    ax1.set_title('Attack Success Rate by Configuration', fontsize=12, fontweight='bold')
    ax1.set_xlim(0, 100)
    ax1.grid(axis='x', alpha=0.3)

    # Color bars based on success rate
    for i, (bar, rate) in enumerate(zip(bars, config_success['success_rate'])):
        if rate == 100:
            bar.set_color('#e74c3c')  # Red for 100%
        elif rate >= 80:
            bar.set_color('#f39c12')  # Orange for 80-99%
        else:
            bar.set_color('#27ae60')  # Green for <80%
        ax1.text(rate + 1, i, f'{rate:.0f}%', va='center', fontsize=9)

    # 2. Time to Crack by Password Category (Top Right)
    ax2 = axes[0, 1]

    # Filter only successful attacks
    successful = df[df['success'] == True].copy()

    categories = ['weak', 'medium', 'strong']
    times_by_category = []

    for cat in categories:
        cat_data = successful[successful['target_category'].str.contains(cat, na=False)]
        times_by_category.append(cat_data['time_to_crack'].tolist())

    bp = ax2.boxplot(times_by_category, labels=[c.capitalize() for c in categories], patch_artist=True)

    # Color the boxes
    colors = ['#2ecc71', '#f39c12', '#e74c3c']
    for patch, color in zip(bp['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)

    ax2.set_ylabel('Time to Crack (seconds)', fontsize=11, fontweight='bold')
    ax2.set_xlabel('Password Category', fontsize=11, fontweight='bold')
    ax2.set_title('Time to Crack by Password Strength', fontsize=12, fontweight='bold')
    ax2.grid(axis='y', alpha=0.3)
    ax2.set_yscale('log')

    # 3. Attempts by Attack Type and Phase (Bottom Left)
    ax3 = axes[1, 0]

    # Group by attack type and phase
    phase1 = df[df['phase'] == 1]
    phase2 = df[df['phase'] == 2]

    attack_types = df['attack_type'].unique()
    x = range(len(attack_types))
    width = 0.35

    phase1_attempts = [phase1[phase1['attack_type'] == at]['total_attempts'].mean() for at in attack_types]
    phase2_attempts = [phase2[phase2['attack_type'] == at]['total_attempts'].mean() for at in attack_types]

    bars1 = ax3.bar([i - width/2 for i in x], phase1_attempts, width, label='Phase 1 (No Protections)', color='#3498db', alpha=0.8)
    bars2 = ax3.bar([i + width/2 for i in x], phase2_attempts, width, label='Phase 2 (With Protections)', color='#e74c3c', alpha=0.8)

    ax3.set_xlabel('Attack Type', fontsize=11, fontweight='bold')
    ax3.set_ylabel('Average Attempts', fontsize=11, fontweight='bold')
    ax3.set_title('Average Attempts by Attack Type and Phase', fontsize=12, fontweight='bold')
    ax3.set_xticks(x)
    ax3.set_xticklabels([at.replace('_', ' ').title() for at in attack_types])
    ax3.legend(fontsize=10)
    ax3.grid(axis='y', alpha=0.3)

    # Add value labels on bars
    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            ax3.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height)}', ha='center', va='bottom', fontsize=9)

    # 4. Protection Mechanism Effectiveness (Bottom Right)
    ax4 = axes[1, 1]

    phase2_data = df[df['phase'] == 2].copy()

    # Calculate effectiveness for each protection
    protections = ['pepper', 'rate_limit', 'lockout', 'captcha', 'totp']
    protection_labels = ['PEPPER', 'RATE LIMIT', 'LOCKOUT', 'CAPTCHA', 'TOTP']
    effectiveness = []

    for prot in protections:
        with_prot = phase2_data[phase2_data[prot] == True]
        if len(with_prot) > 0:
            success_rate = (with_prot['success'].sum() / len(with_prot)) * 100
            effectiveness.append(100 - success_rate)  # Higher is better (blocks more)
        else:
            effectiveness.append(0)

    bars = ax4.bar(range(len(protection_labels)), effectiveness, color=['#3498db', '#9b59b6', '#e67e22', '#1abc9c', '#e74c3c'], alpha=0.8)
    ax4.set_xlabel('Protection Mechanism', fontsize=11, fontweight='bold')
    ax4.set_ylabel('Effectiveness (% Attacks Blocked)', fontsize=11, fontweight='bold')
    ax4.set_title('Protection Mechanism Effectiveness', fontsize=12, fontweight='bold')
    ax4.set_xticks(range(len(protection_labels)))
    ax4.set_xticklabels(protection_labels, rotation=45, ha='right')
    ax4.set_ylim(0, 100)
    ax4.grid(axis='y', alpha=0.3)

    # Add value labels
    for i, (bar, val) in enumerate(zip(bars, effectiveness)):
        ax4.text(i, val + 2, f'{val:.1f}%', ha='center', fontsize=10, fontweight='bold')

    plt.tight_layout()

    # Save the figure
    filepath = os.path.join(output_dir, "combined_analysis.png")
    plt.savefig(filepath, dpi=200, bbox_inches='tight')
    plt.close()

    print(f"✓ Combined graph generated: {filepath}")

    return filepath


def main():
    print("="*80)
    print("GENERATING COMBINED ANALYSIS GRAPH")
    print("="*80)

    # Find the most recent summary CSV
    summary_files = glob.glob("results/experiments/experiment_summary_*.csv")
    if not summary_files:
        print("ERROR: No experiment summary CSV found!")
        return

    summary_file = max(summary_files, key=os.path.getctime)
    print(f"\nUsing summary file: {os.path.basename(summary_file)}")

    filepath = generate_combined_graph(summary_file)

    print(f"\n✓ Combined graph saved to: {filepath}")
    print("\nYou can now view this comprehensive analysis graph!")


if __name__ == "__main__":
    main()
