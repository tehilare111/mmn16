import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
import glob
from datetime import datetime
import json

sys.path.insert(0, '.')


def load_summary_csv(summary_file: str) -> pd.DataFrame:
    """Load the experiment summary CSV"""
    return pd.read_csv(summary_file)


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
    target = parts[2] if parts[0] == "brute" else parts[2]
    hash_mode = parts[3] if parts[0] == "brute" else parts[3]

    # Find defense flags (everything between hash_mode and timestamp)
    defense_parts = []
    for i in range(4 if parts[0] == "brute" else 4, len(parts) - 1):
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


def generate_attack_graphs(results_dir: str = "results", output_dir: str = "results/analysis"):
    """Generate graphs for all attacks grouped by configuration"""
    os.makedirs(output_dir, exist_ok=True)

    # Find all CSV files
    csv_files = find_attack_csvs(results_dir)
    print(f"Found {len(csv_files)} attack result files")

    # Parse and group by configuration
    attacks = []
    for csv_file in csv_files:
        metadata = parse_filename(csv_file)
        if metadata:
            attacks.append(metadata)

    # Group by attack_type, hash_mode, and defenses
    configurations = {}
    for attack in attacks:
        key = (attack['attack_type'], attack['hash_mode'], attack['defenses'])
        if key not in configurations:
            configurations[key] = []
        configurations[key].append(attack)

    print(f"\nGenerating graphs for {len(configurations)} configurations...")

    graph_count = 0
    for (attack_type, hash_mode, defenses), attack_list in configurations.items():
        # Create a figure for this configuration
        fig, ax = plt.subplots(figsize=(12, 7))

        config_title = f"{attack_type.replace('_', ' ').title()} - {hash_mode}"
        if defenses != "nodefense":
            config_title += f" - {defenses.replace('_', ', ').upper()}"
        else:
            config_title += " - No Protections"

        has_data = False

        # Plot each target (weak, medium, strong)
        for attack in attack_list:
            try:
                df = load_and_process_attack_csv(attack['filename'])

                if len(df) == 0:
                    continue

                category = categorize_target(attack['target'])

                # Plot cumulative attempts vs time
                color_map = {"weak": "green", "medium": "orange", "strong": "red"}
                color = color_map.get(category, "blue")

                # Mark successful attempts
                successful = df[df['success'] == True]

                ax.plot(df['attempt'], df['time_from_start'],
                       label=f"{category.capitalize()} - {attack['target']}",
                       color=color, linewidth=2, alpha=0.7)

                # Mark the success point with a star
                if len(successful) > 0:
                    success_point = successful.iloc[0]
                    ax.scatter([success_point['attempt']], [success_point['time_from_start']],
                              color=color, marker='*', s=300, zorder=5,
                              edgecolors='black', linewidths=1.5)

                has_data = True

            except Exception as e:
                print(f"Error processing {attack['filename']}: {e}")
                continue

        if has_data:
            ax.set_xlabel('Attempt Number', fontsize=12, fontweight='bold')
            ax.set_ylabel('Time from Start (seconds)', fontsize=12, fontweight='bold')
            ax.set_title(config_title, fontsize=14, fontweight='bold', pad=20)
            ax.legend(loc='best', fontsize=10)
            ax.grid(True, alpha=0.3)

            # Save the figure
            filename = f"{attack_type}_{hash_mode}_{defenses}.png"
            filepath = os.path.join(output_dir, filename)
            plt.tight_layout()
            plt.savefig(filepath, dpi=150, bbox_inches='tight')
            plt.close()

            graph_count += 1
            print(f"  ✓ Generated: {filename}")

    print(f"\n✓ Total graphs generated: {graph_count}")
    print(f"✓ Graphs saved to: {output_dir}/")

    return graph_count


def generate_summary_statistics(summary_file: str) -> dict:
    """Generate summary statistics from the experiment summary CSV"""
    df = load_summary_csv(summary_file)

    stats = {}

    # Overall statistics
    stats['total_experiments'] = len(df)
    stats['successful_attacks'] = df['success'].sum()
    stats['success_rate'] = (stats['successful_attacks'] / stats['total_experiments'] * 100)

    # By phase
    stats['phase1_success'] = df[df['phase'] == 1]['success'].sum()
    stats['phase1_total'] = len(df[df['phase'] == 1])
    stats['phase2_success'] = df[df['phase'] == 2]['success'].sum()
    stats['phase2_total'] = len(df[df['phase'] == 2])

    # By hash mode
    stats['by_hash_mode'] = {}
    for hash_mode in df['hash_mode'].unique():
        hash_df = df[df['hash_mode'] == hash_mode]
        stats['by_hash_mode'][hash_mode] = {
            'total': len(hash_df),
            'successful': hash_df['success'].sum(),
            'avg_time_to_crack': hash_df[hash_df['success'] == True]['time_to_crack'].mean(),
            'avg_attempts': hash_df['total_attempts'].mean(),
            'avg_latency_ms': hash_df['avg_latency_ms'].mean()
        }

    # By target category
    stats['by_category'] = {}
    for category in ['weak', 'medium', 'strong']:
        cat_df = df[df['target_category'].str.contains(category, na=False)]
        if len(cat_df) > 0:
            stats['by_category'][category] = {
                'total': len(cat_df),
                'successful': cat_df['success'].sum(),
                'avg_time_to_crack': cat_df[cat_df['success'] == True]['time_to_crack'].mean(),
                'avg_attempts': cat_df['total_attempts'].mean()
            }

    # By attack type
    stats['by_attack_type'] = {}
    for attack_type in df['attack_type'].unique():
        attack_df = df[df['attack_type'] == attack_type]
        stats['by_attack_type'][attack_type] = {
            'total': len(attack_df),
            'successful': attack_df['success'].sum(),
            'avg_time': attack_df['total_time_seconds'].mean()
        }

    return stats


def print_summary_report(stats: dict):
    """Print a formatted summary report"""
    print("\n" + "="*80)
    print("EXPERIMENT ANALYSIS SUMMARY")
    print("="*80)

    print(f"\n{'Overall Statistics':-^80}")
    print(f"Total Experiments: {stats['total_experiments']}")
    print(f"Successful Attacks: {stats['successful_attacks']}")
    print(f"Success Rate: {stats['success_rate']:.1f}%")

    print(f"\n{'By Phase':-^80}")
    print(f"Phase 1 (Hash Comparison): {stats['phase1_success']}/{stats['phase1_total']} successful")
    print(f"Phase 2 (Protections): {stats['phase2_success']}/{stats['phase2_total']} successful")

    print(f"\n{'By Hash Algorithm':-^80}")
    for hash_mode, data in stats['by_hash_mode'].items():
        print(f"\n{hash_mode}:")
        print(f"  Success Rate: {data['successful']}/{data['total']}")
        print(f"  Avg Time to Crack: {data['avg_time_to_crack']:.2f}s")
        print(f"  Avg Attempts: {data['avg_attempts']:.1f}")
        print(f"  Avg Latency: {data['avg_latency_ms']:.2f}ms")

    print(f"\n{'By Password Category':-^80}")
    for category, data in stats['by_category'].items():
        print(f"\n{category.capitalize()}:")
        print(f"  Success Rate: {data['successful']}/{data['total']}")
        print(f"  Avg Time to Crack: {data['avg_time_to_crack']:.2f}s")
        print(f"  Avg Attempts: {data['avg_attempts']:.1f}")

    print(f"\n{'By Attack Type':-^80}")
    for attack_type, data in stats['by_attack_type'].items():
        print(f"\n{attack_type}:")
        print(f"  Success Rate: {data['successful']}/{data['total']}")
        print(f"  Avg Time: {data['avg_time']:.2f}s")

    print("\n" + "="*80)


def save_statistics_to_file(stats: dict, output_dir: str = "results/analysis"):
    """Save statistics to JSON file"""
    import numpy as np

    def convert_to_json_serializable(obj):
        """Convert numpy types to Python native types"""
        if isinstance(obj, dict):
            return {key: convert_to_json_serializable(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [convert_to_json_serializable(item) for item in obj]
        elif isinstance(obj, (np.integer, np.int64, np.int32)):
            return int(obj)
        elif isinstance(obj, (np.floating, np.float64, np.float32)):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif pd.isna(obj):
            return None
        return obj

    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(output_dir, f"analysis_summary_{timestamp}.json")

    # Convert stats to JSON-serializable format
    serializable_stats = convert_to_json_serializable(stats)

    with open(filepath, 'w') as f:
        json.dump(serializable_stats, f, indent=2)

    print(f"\n✓ Statistics saved to: {filepath}")


def main():
    print("="*80)
    print("EXPERIMENT RESULTS ANALYSIS")
    print("="*80)

    # Find the most recent summary CSV
    summary_files = glob.glob("results/experiments/experiment_summary_*.csv")
    if not summary_files:
        print("ERROR: No experiment summary CSV found!")
        print("Please run experiments first: python experiments/run_all.py")
        return

    summary_file = max(summary_files, key=os.path.getctime)
    print(f"\nUsing summary file: {os.path.basename(summary_file)}")

    # Generate summary statistics
    print("\n" + "-"*80)
    print("Generating Summary Statistics...")
    print("-"*80)
    stats = generate_summary_statistics(summary_file)
    print_summary_report(stats)
    save_statistics_to_file(stats)

    # Generate graphs
    print("\n" + "-"*80)
    print("Generating Attack Visualizations...")
    print("-"*80)
    graph_count = generate_attack_graphs()

    print("\n" + "="*80)
    print("ANALYSIS COMPLETE!")
    print("="*80)
    print(f"\n✓ Summary statistics: results/analysis/analysis_summary_*.json")
    print(f"✓ Visualization graphs: results/analysis/*.png ({graph_count} graphs)")
    print("\nYou can now use these results for your research report!")


if __name__ == "__main__":
    main()
