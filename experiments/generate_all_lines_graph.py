import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
import glob

sys.path.insert(0, '.')


def find_attack_csvs(results_dir: str = "results") -> list:
    """Find all attack result CSV files"""
    pattern = os.path.join(results_dir, "*_*.csv")
    csv_files = glob.glob(pattern)
    # Exclude experiment summary files
    csv_files = [f for f in csv_files if "experiment_summary" not in f]
    return csv_files


def parse_filename(filename: str) -> dict:
    """Parse attack CSV filename to extract metadata"""
    basename = os.path.basename(filename)
    parts = basename.replace(".csv", "").split("_")

    if len(parts) < 4:
        return None

    attack_type = parts[0] + "_" + parts[1] if parts[0] in ["brute", "password"] else parts[0]
    target = parts[2]
    hash_mode = parts[3]

    # Find defense flags (everything between hash_mode and timestamp)
    defense_parts = []
    for i in range(4, len(parts) - 1):
        if not parts[i].isdigit():
            defense_parts.append(parts[i])

    defense_str = "_".join(defense_parts) if defense_parts else "nodefense"

    return {
        "attack_type": attack_type,
        "target": target,
        "hash_mode": hash_mode,
        "defenses": defense_str,
        "filename": filename
    }


def categorize_target(target: str) -> str:
    """Determine category from target username"""
    if "weak" in target:
        return "weak"
    elif "medium" in target:
        return "medium"
    elif "strong" in target:
        return "strong"
    return "unknown"


def load_and_process_attack_csv(csv_file: str) -> pd.DataFrame:
    """Load an attack CSV and add cumulative time"""
    df = pd.read_csv(csv_file)

    # Calculate cumulative time from start
    if 'timestamp' in df.columns:
        df['time_from_start'] = df['timestamp'] - df['timestamp'].iloc[0]
    else:
        # Fallback: use attempt number as proxy for time
        df['time_from_start'] = df['attempt'] * 0.3  # Assume ~300ms per attempt

    return df


def generate_all_lines_graph(results_dir: str = "results", output_dir: str = "results/analysis"):
    """Generate a single graph with all attack lines"""
    os.makedirs(output_dir, exist_ok=True)

    # Find all CSV files
    csv_files = find_attack_csvs(results_dir)
    print(f"Found {len(csv_files)} attack result files")

    # Parse and categorize attacks
    attacks = []
    for csv_file in csv_files:
        metadata = parse_filename(csv_file)
        if metadata:
            attacks.append(metadata)

    # Create two subplots: one for brute force, one for password spraying
    fig, axes = plt.subplots(1, 2, figsize=(24, 10))
    fig.suptitle('All Attack Progressions - Complete Dataset', fontsize=16, fontweight='bold')

    # Color mapping for categories
    category_colors = {"weak": "#2ecc71", "medium": "#f39c12", "strong": "#e74c3c"}

    # Defense styling
    defense_styles = {
        "nodefense": {'linestyle': '-', 'linewidth': 2.5, 'alpha': 0.8},
        "pepper": {'linestyle': '--', 'linewidth': 2, 'alpha': 0.7},
        "ratelimit": {'linestyle': '-.', 'linewidth': 2, 'alpha': 0.7},
        "lockout": {'linestyle': ':', 'linewidth': 2.5, 'alpha': 0.7},
        "captcha": {'linestyle': '-', 'linewidth': 1.5, 'alpha': 0.6},
        "totp": {'linestyle': '--', 'linewidth': 1.5, 'alpha': 0.6}
    }

    attack_types = ["brute_force", "password_spraying"]

    for idx, attack_type in enumerate(attack_types):
        ax = axes[idx]

        # Filter attacks for this type
        type_attacks = [a for a in attacks if a['attack_type'] == attack_type]

        plotted_count = 0

        for attack in type_attacks:
            try:
                df = load_and_process_attack_csv(attack['filename'])

                if len(df) == 0:
                    continue

                category = categorize_target(attack['target'])
                defense = attack['defenses']

                # Get color and style
                color = category_colors.get(category, "blue")
                style = defense_styles.get(defense, defense_styles['nodefense'])

                # Create label
                label = f"{category} - {defense} - {attack['hash_mode']}"

                # Plot the line
                ax.plot(df['attempt'], df['time_from_start'],
                       label=label,
                       color=color,
                       linestyle=style['linestyle'],
                       linewidth=style['linewidth'],
                       alpha=style['alpha'])

                # Mark successful attempts with a star
                successful = df[df['success'] == True]
                if len(successful) > 0:
                    success_point = successful.iloc[0]
                    ax.scatter([success_point['attempt']], [success_point['time_from_start']],
                              color=color, marker='*', s=200, zorder=5,
                              edgecolors='black', linewidths=1)

                plotted_count += 1

            except Exception as e:
                print(f"Error processing {attack['filename']}: {e}")
                continue

        # Customize subplot
        ax.set_xlabel('Attempt Number', fontsize=12, fontweight='bold')
        ax.set_ylabel('Time from Start (seconds)', fontsize=12, fontweight='bold')

        title = "Brute Force Attacks" if attack_type == "brute_force" else "Password Spraying Attacks"
        ax.set_title(f"{title} - All Configurations ({plotted_count} attacks)",
                     fontsize=13, fontweight='bold', pad=15)

        # Only show legend if not too many items
        if plotted_count <= 30:
            ax.legend(loc='upper left', fontsize=7, ncol=2)
        else:
            # Add a simplified legend
            from matplotlib.lines import Line2D
            legend_elements = [
                Line2D([0], [0], color='#2ecc71', lw=2, label='Weak passwords'),
                Line2D([0], [0], color='#f39c12', lw=2, label='Medium passwords'),
                Line2D([0], [0], color='#e74c3c', lw=2, label='Strong passwords'),
                Line2D([0], [0], color='gray', linestyle='-', lw=2, label='No defense'),
                Line2D([0], [0], color='gray', linestyle='--', lw=2, label='PEPPER/TOTP'),
                Line2D([0], [0], color='gray', linestyle='-.', lw=2, label='RATE_LIMIT'),
                Line2D([0], [0], color='gray', linestyle=':', lw=2, label='LOCKOUT'),
            ]
            ax.legend(handles=legend_elements, loc='upper left', fontsize=9)

        ax.grid(True, alpha=0.3)
        ax.set_xlim(left=0)
        ax.set_ylim(bottom=0)

    plt.tight_layout()

    # Save the figure
    filepath = os.path.join(output_dir, "all_attacks_combined.png")
    plt.savefig(filepath, dpi=200, bbox_inches='tight')
    plt.close()

    print(f"✓ All-in-one graph generated: {filepath}")

    return filepath


def main():
    print("="*80)
    print("GENERATING ALL ATTACK LINES COMBINED GRAPH")
    print("="*80)

    filepath = generate_all_lines_graph()

    print(f"\n✓ Combined attack lines graph saved to: {filepath}")
    print("\nThis graph shows ALL attack progressions on the same plot!")


if __name__ == "__main__":
    main()
