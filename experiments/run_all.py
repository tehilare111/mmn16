import os
import sys
import time
import signal
import subprocess
import asyncio
import importlib
import json
import csv
from datetime import datetime
from typing import Optional
import httpx
from dotenv import dotenv_values

sys.path.insert(0, '.')


ENV_FILE: str = ".env"
SERVER_PORT: int = 8001
SERVER_HOST: str = "localhost"
BASE_URL: str = f"http://{SERVER_HOST}:{SERVER_PORT}"
SERVER_STARTUP_WAIT: float = 3.0
HEALTH_CHECK_TIMEOUT: float = 30.0
HEALTH_CHECK_INTERVAL: float = 1.0


def read_current_config() -> dict:
    """Read current .env configuration and return as dict"""
    config = dotenv_values(ENV_FILE)
    return {
        "hash_mode": config.get("HASH_MODE", "SHA256"),
        "rate_limit": config.get("RATE_LIMIT", "false").lower() == "true",
        "lockout": config.get("LOCKOUT", "false").lower() == "true",
        "captcha": config.get("CAPTCHA", "false").lower() == "true",
        "pepper": config.get("PEPPER", "false").lower() == "true",
        "totp": config.get("TOTP", "false").lower() == "true"
    }


def update_env_file(config: dict) -> None:
    if not os.path.exists(ENV_FILE):
        raise FileNotFoundError(f"{ENV_FILE} not found")

    with open(ENV_FILE, "r") as f:
        lines = f.readlines()

    updates = {
        "HASH_MODE": config["hash_mode"],
        "RATE_LIMIT": str(config["rate_limit"]).lower(),
        "LOCKOUT": str(config["lockout"]).lower(),
        "CAPTCHA": str(config["captcha"]).lower(),
        "PEPPER": str(config["pepper"]).lower(),
        "TOTP": str(config["totp"]).lower()
    }

    new_lines = []
    for line in lines:
        updated = False
        for key, value in updates.items():
            if line.startswith(f"{key}="):
                new_lines.append(f"{key}={value}\n")
                updated = True
                break
        if not updated:
            new_lines.append(line)

    with open(ENV_FILE, "w") as f:
        f.writelines(new_lines)


def kill_existing_servers() -> None:
    try:
        subprocess.run(["pkill", "-9", "-f", "uvicorn"], capture_output=True)
        time.sleep(2.0)
    except Exception:
        pass
    try:
        subprocess.run(["lsof", "-ti", f":{SERVER_PORT}"], capture_output=True)
        subprocess.run(["kill", "-9", "$(lsof -ti :{})".format(SERVER_PORT)], shell=True, capture_output=True)
        time.sleep(1.0)
    except Exception:
        pass


def start_server() -> subprocess.Popen:
    process = subprocess.Popen(
        ["uvicorn", "src.main:app", "--port", str(SERVER_PORT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid
    )
    time.sleep(SERVER_STARTUP_WAIT)
    if process.poll() is not None:
        stdout, stderr = process.communicate()
        print(f"Server process exited early with code {process.returncode}")
        if stderr:
            print(f"Server stderr: {stderr.decode()}")
        if stdout:
            print(f"Server stdout: {stdout.decode()}")
    return process


async def wait_for_server_ready(process: Optional[subprocess.Popen] = None) -> bool:
    start_time = time.time()
    async with httpx.AsyncClient(timeout=5.0) as client:
        while time.time() - start_time < HEALTH_CHECK_TIMEOUT:
            if process and process.poll() is not None:
                stdout, stderr = process.communicate()
                print(f"Server process died during health check with code {process.returncode}")
                if stderr:
                    print(f"Server stderr: {stderr.decode()}")
                if stdout:
                    print(f"Server stdout: {stdout.decode()}")
                return False
            try:
                response = await client.get(f"{BASE_URL}/admin/get_captcha_token")
                if response.status_code in [200, 400, 404]:
                    return True
            except Exception:
                pass
            await asyncio.sleep(HEALTH_CHECK_INTERVAL)
    if process:
        try:
            stdout = process.stdout.read() if process.stdout else b""
            stderr = process.stderr.read() if process.stderr else b""
            if stderr:
                print(f"Server stderr after timeout: {stderr.decode()}")
            if stdout:
                print(f"Server stdout after timeout: {stdout.decode()}")
        except Exception:
            pass
    return False


def stop_server(process: Optional[subprocess.Popen]) -> None:
    if process:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            process.wait(timeout=5)
        except Exception:
            pass
    kill_existing_servers()
    time.sleep(2.0)


def generate_configuration_matrix() -> list:
    configs = []

    hash_modes = ["SHA256", "BCRYPT", "ARGON2ID"]

    for hash_mode in hash_modes:
        configs.append({
            "phase": 1,
            "hash_mode": hash_mode,
            "rate_limit": False,
            "lockout": False,
            "captcha": False,
            "pepper": False,
            "totp": False,
            "description": f"Phase 1: {hash_mode} - No protections"
        })

    strongest_hash = "ARGON2ID"

    protection_configs = [
        {"pepper": True, "description": "PEPPER only"},
        {"rate_limit": True, "description": "RATE_LIMIT only"},
        {"lockout": True, "description": "LOCKOUT only"},
        {"captcha": True, "description": "CAPTCHA only"},
        {"totp": True, "description": "TOTP only"},
        {"pepper": True, "rate_limit": True, "lockout": True, "captcha": True, "totp": True, "description": "ALL protections"},
    ]

    for prot_config in protection_configs:
        config = {
            "phase": 2,
            "hash_mode": strongest_hash,
            "rate_limit": prot_config.get("rate_limit", False),
            "lockout": prot_config.get("lockout", False),
            "captcha": prot_config.get("captcha", False),
            "pepper": prot_config.get("pepper", False),
            "totp": prot_config.get("totp", False),
            "description": f"Phase 2: {strongest_hash} - {prot_config['description']}"
        }
        configs.append(config)

    return configs


def generate_attack_plan() -> list:
    attacks = []

    # attacks.append({
    #     "type": "brute_force",
    #     "target": "weak_user_01",
    #     "category": "weak"
    # })
    # attacks.append({
    #     "type": "brute_force",
    #     "target": "medium_user_01",
    #     "category": "medium"
    # })
    # attacks.append({
    #     "type": "brute_force",
    #     "target": "strong_user_01",
    #     "category": "strong"
    # })

    weak_users = [f"weak_user_{i:02d}" for i in range(1, 11)]
    attacks.append({
        "type": "password_spraying",
        "targets": weak_users,
        "category": "weak_group"
    })

    medium_users = [f"medium_user_{i:02d}" for i in range(1, 11)]
    attacks.append({
        "type": "password_spraying",
        "targets": medium_users,
        "category": "medium_group"
    })

    strong_users = [f"strong_user_{i:02d}" for i in range(1, 11)]
    attacks.append({
        "type": "password_spraying",
        "targets": strong_users,
        "category": "strong_group"
    })

    return attacks


async def run_single_attack(attack: dict) -> Optional[dict]:
    try:
        # Read current configuration from .env
        current_config = read_current_config()

        # Import attack modules (no need to reload, we pass config explicitly)
        from tests.brute_force import brute_force_attack
        from tests.password_spraying import password_spraying_attack

        if attack["type"] == "brute_force":
            result = await brute_force_attack(
                target_username=attack["target"],
                protection_flags=current_config,
                hash_mode=current_config["hash_mode"]
            )
        elif attack["type"] == "password_spraying":
            result = await password_spraying_attack(
                target_usernames=attack["targets"],
                protection_flags=current_config,
                hash_mode=current_config["hash_mode"]
            )
        else:
            return None
        return result
    except Exception as e:
        import traceback
        print(f"Error running attack: {e}")
        print(traceback.format_exc())
        return None


def save_experiment_log(log_entries: list, output_dir: str = "results/experiments") -> str:
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(output_dir, f"experiment_log_{timestamp}.txt")

    with open(log_file, "w") as f:
        for entry in log_entries:
            f.write(f"{entry}\n")

    return log_file


def save_summary_csv(summary_data: list, output_dir: str = "results/experiments") -> str:
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_file = os.path.join(output_dir, f"experiment_summary_{timestamp}.csv")

    if not summary_data:
        return csv_file

    fieldnames = list(summary_data[0].keys())

    with open(csv_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(summary_data)

    return csv_file


async def main() -> None:
    print("=" * 80)
    print("EXPERIMENT RUNNER - Authentication Security Research")
    print("=" * 80)
    print()

    configs = generate_configuration_matrix()
    attacks = generate_attack_plan()

    total_experiments = len(configs) * len(attacks)

    print(f"Total configurations: {len(configs)}")
    print(f"Attacks per configuration: {len(attacks)}")
    print(f"Total experiments: {total_experiments}")
    print()

    log_entries = []
    summary_data = []
    experiment_count = 0
    start_time_overall = time.time()

    for config_idx, config in enumerate(configs, 1):
        print(f"\n{'='*80}")
        print(f"Configuration {config_idx}/{len(configs)}: {config['description']}")
        print(f"{'='*80}")

        log_entries.append(f"\n{'='*80}")
        log_entries.append(f"Configuration {config_idx}/{len(configs)}: {config['description']}")
        log_entries.append(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        kill_existing_servers()

        update_env_file(config)
        print(f"Updated .env file with configuration")
        log_entries.append("Updated .env file")

        server_process = start_server()
        print(f"Starting server...")

        server_ready = await wait_for_server_ready(server_process)
        if not server_ready:
            print("ERROR: Server failed to start!")
            log_entries.append("ERROR: Server failed to start")
            stop_server(server_process)
            continue

        print(f"Server ready!")
        log_entries.append("Server started successfully")

        print(f"Seeding users with current hash mode...")
        seed_result = subprocess.run(
            ["python", "scripts/seed_users.py"],
            capture_output=True,
            text=True
        )
        if seed_result.returncode == 0:
            print(f"Users seeded successfully")
            log_entries.append("Users seeded successfully")
        else:
            print(f"WARNING: User seeding failed: {seed_result.stderr}")
            log_entries.append(f"WARNING: User seeding failed")

        for attack_idx, attack in enumerate(attacks, 1):
            experiment_count += 1

            attack_desc = f"{attack['type']} - {attack.get('target', attack.get('category'))}"
            print(f"\n  [{experiment_count}/{total_experiments}] Running: {attack_desc}")
            log_entries.append(f"  [{experiment_count}/{total_experiments}] {attack_desc}")

            attack_start = time.time()
            result = await run_single_attack(attack)
            attack_duration = time.time() - attack_start

            if result:
                summary_entry = {
                    "experiment_id": experiment_count,
                    "phase": config["phase"],
                    "config_description": config["description"],
                    "hash_mode": config["hash_mode"],
                    "rate_limit": config["rate_limit"],
                    "lockout": config["lockout"],
                    "captcha": config["captcha"],
                    "pepper": config["pepper"],
                    "totp": config["totp"],
                    "attack_type": attack["type"],
                    "target": attack.get("target", attack.get("category")),
                    "target_category": attack["category"],
                    "success": result.get("success", False),
                    "total_attempts": result.get("total_attempts", 0),
                    "time_to_crack": result.get("time_to_crack"),
                    "total_time_seconds": result.get("total_time_seconds", attack_duration),
                    "avg_latency_ms": result.get("avg_latency_ms", 0),
                    "attempts_per_second": result.get("attempts_per_second", 0)
                }
                summary_data.append(summary_entry)

                status = "SUCCESS" if result.get("success") else "FAILED"
                print(f"    Status: {status} | Attempts: {result.get('total_attempts', 0)} | Time: {attack_duration:.2f}s")
                log_entries.append(f"    Status: {status} | Attempts: {result.get('total_attempts', 0)} | Time: {attack_duration:.2f}s")

        stop_server(server_process)
        print(f"\nStopped server")
        log_entries.append("Server stopped")

        elapsed_time = time.time() - start_time_overall
        avg_time_per_exp = elapsed_time / experiment_count if experiment_count > 0 else 0
        remaining_experiments = total_experiments - experiment_count
        estimated_remaining = avg_time_per_exp * remaining_experiments

        print(f"\nProgress: {experiment_count}/{total_experiments} experiments completed")
        print(f"Elapsed time: {elapsed_time/60:.1f} minutes")
        print(f"Estimated remaining time: {estimated_remaining/60:.1f} minutes")

    print(f"\n{'='*80}")
    print("ALL EXPERIMENTS COMPLETED!")
    print(f"{'='*80}")

    total_time = time.time() - start_time_overall
    print(f"\nTotal experiments: {experiment_count}")
    print(f"Total time: {total_time/60:.1f} minutes ({total_time/3600:.2f} hours)")

    log_file = save_experiment_log(log_entries)
    print(f"\nLog file saved: {log_file}")

    csv_file = save_summary_csv(summary_data)
    print(f"Summary CSV saved: {csv_file}")

    print(f"\n{'='*80}")
    print("Experiment Results Summary:")
    print(f"{'='*80}")

    phase1_success = sum(1 for entry in summary_data if entry["phase"] == 1 and entry["success"])
    phase1_total = sum(1 for entry in summary_data if entry["phase"] == 1)
    phase2_success = sum(1 for entry in summary_data if entry["phase"] == 2 and entry["success"])
    phase2_total = sum(1 for entry in summary_data if entry["phase"] == 2)

    print(f"Phase 1 (Hash Comparison): {phase1_success}/{phase1_total} successful attacks")
    print(f"Phase 2 (Protections): {phase2_success}/{phase2_total} successful attacks")
    print()

    kill_existing_servers()


if __name__ == "__main__":
    asyncio.run(main())
