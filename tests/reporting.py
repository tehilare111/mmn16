import json
import csv
import os
from datetime import datetime


def calculate_success_rate_by_category(results):
    categories = {"weak": {"attempts": 0, "successes": 0},
                  "medium": {"attempts": 0, "successes": 0},
                  "strong": {"attempts": 0, "successes": 0}}

    for result in results:
        category = result.get("password_category", "unknown")
        if category in categories:
            categories[category]["attempts"] += 1
            if result.get("success", False):
                categories[category]["successes"] += 1

    for category in categories:
        attempts = categories[category]["attempts"]
        successes = categories[category]["successes"]
        categories[category]["success_rate"] = (successes / attempts) if attempts > 0 else 0.0

    return categories


def calculate_average_latency(results):
    if not results:
        return 0.0
    total_latency = sum(r.get("latency_ms", 0) for r in results)
    return total_latency / len(results)


def print_attack_summary(report):
    print("\n" + "="*80)
    print(f"ATTACK SUMMARY: {report['attack_type'].upper()}")
    print("="*80)

    print(f"\nTarget: {report['target_username']} ({report['target_category']})")
    print(f"Group Seed: {report['group_seed']}")
    print(f"Hash Mode: {report['hash_mode']}")

    print("\nProtection Flags:")
    for flag, enabled in report['protection_flags'].items():
        status = "ENABLED" if enabled else "disabled"
        print(f"  - {flag}: {status}")

    print(f"\nTotal Attempts: {report['total_attempts']}")
    print(f"Total Time: {report['total_time_seconds']:.2f}s")
    print(f"Attempts/Second: {report['attempts_per_second']:.2f}")
    print(f"Average Latency: {report['avg_latency_ms']:.2f}ms")

    print(f"\nSuccess: {report['success']}")
    if report['success']:
        print(f"Correct Password: {report['correct_password']}")
        print(f"Time to Crack: {report['time_to_crack']:.2f}s")

    print("\nSuccess Rate by Password Category:")
    for category, stats in report['success_rate_by_category'].items():
        print(f"  - {category}: {stats['successes']}/{stats['attempts']} ({stats['success_rate']*100:.1f}%)")

    print("="*80 + "\n")


def generate_filename(attack_type, target_username, hash_mode, protection_flags, extension="json"):
    defenses = []
    if protection_flags.get("rate_limit", False):
        defenses.append("ratelimit")
    if protection_flags.get("lockout", False):
        defenses.append("lockout")
    if protection_flags.get("captcha", False):
        defenses.append("captcha")
    if protection_flags.get("pepper", False):
        defenses.append("pepper")
    if protection_flags.get("totp", False):
        defenses.append("totp")

    defense_str = "_".join(defenses) if defenses else "nodefense"
    timestamp = int(datetime.now().timestamp())

    return f"{attack_type}_{target_username}_{hash_mode}_{defense_str}_{timestamp}.{extension}"


def save_results_json(report, output_dir="results"):
    os.makedirs(output_dir, exist_ok=True)

    filename = generate_filename(
        attack_type=report["attack_type"],
        target_username=report["target_username"],
        hash_mode=report["hash_mode"],
        protection_flags=report["protection_flags"],
        extension="json"
    )

    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w") as f:
        json.dump(report, f, indent=2)

    return filepath


def save_results_csv(report, output_dir="results"):
    os.makedirs(output_dir, exist_ok=True)

    filename = generate_filename(
        attack_type=report["attack_type"],
        target_username=report["target_username"],
        hash_mode=report["hash_mode"],
        protection_flags=report["protection_flags"],
        extension="csv"
    )

    filepath = os.path.join(output_dir, filename)

    if not report.get("results"):
        return filepath

    fieldnames = [
        "attempt",
        "timestamp",
        "group_seed",
        "username",
        "password",
        "password_category",
        "hash_mode",
        "rate_limit",
        "lockout",
        "captcha",
        "pepper",
        "totp",
        "status_code",
        "success",
        "latency_ms",
        "error"
    ]

    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for result in report["results"]:
            row = {
                "attempt": result["attempt"],
                "timestamp": result["timestamp"],
                "group_seed": result["group_seed"],
                "username": result["username"],
                "password": result["password"],
                "password_category": result["password_category"],
                "hash_mode": result["hash_mode"],
                "rate_limit": result["protection_flags"]["rate_limit"],
                "lockout": result["protection_flags"]["lockout"],
                "captcha": result["protection_flags"]["captcha"],
                "pepper": result["protection_flags"]["pepper"],
                "totp": result["protection_flags"]["totp"],
                "status_code": result["status_code"],
                "success": result["success"],
                "latency_ms": round(result["latency_ms"], 2),
                "error": result.get("error", "")
            }
            writer.writerow(row)

    return filepath


def save_attack_results(report, output_dir="results"):
    json_path = save_results_json(report, output_dir)
    csv_path = save_results_csv(report, output_dir)
    return json_path, csv_path
