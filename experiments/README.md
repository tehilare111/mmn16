# Experiment Runner

Automated experiment suite for testing authentication security mechanisms against brute force and password spraying attacks.

## Overview

The experiment runner systematically tests all combinations of:
- Hash algorithms (SHA256, BCRYPT, ARGON2ID)
- Protection mechanisms (PEPPER, RATE_LIMIT, LOCKOUT, CAPTCHA, TOTP)
- Attack types (brute force, password spraying)
- User categories (weak, medium, strong passwords)

## Files

- `run_all.py` - Main experiment orchestration script
- `test_setup.py` - Validation script to check configuration before running
- `README.md` - This file

## Experiment Matrix

### Phase 1: Hash Algorithm Comparison (18 experiments)
Tests all 3 hash modes with NO protections enabled:
- SHA256, BCRYPT, ARGON2ID
- 3 brute force attacks per hash (weak, medium, strong user)
- 3 password spray attacks per hash (weak group, medium group, strong group)

### Phase 2: Protection Mechanisms (36 experiments)
Uses strongest hash from Phase 1 (typically ARGON2ID):
- Tests protections individually (weakest → strongest):
  1. PEPPER only
  2. RATE_LIMIT only
  3. LOCKOUT only
  4. CAPTCHA only
  5. TOTP only
  6. ALL protections combined
- 6 attacks per configuration (3 brute force + 3 password spray)

**Total: 54 experiments**

## Common Password List

The experiments use a realistic common password list (`data/common_passwords.txt`):
- ~464 passwords total
- Includes all 30 real user passwords embedded naturally
- Organized by strength:
  - Weak section (indices 0-100+): Simple passwords, all weak user passwords
  - Medium section (indices 100-300+): Complex passwords, all medium user passwords
  - Strong section (indices 300+): Very complex passwords, all strong user passwords

This simulates a real-world attacker who doesn't know which passwords are correct.

## Usage

### 1. Validate Setup
```bash
python experiments/test_setup.py
```

This checks:
- Common password list exists and contains all real passwords
- Passwords are properly ordered by strength
- All imports work correctly
- .env file is present

### 2. Run Full Experiment Suite
```bash
python experiments/run_all.py
```

The script will:
- Kill any existing servers
- For each configuration:
  - Update .env file
  - Restart server
  - Wait for server to be ready
  - Run all 6 attacks (3 brute force + 3 password spray)
  - Stop server
- Generate summary CSV and log file
- Display progress and time estimates

### 3. Monitor Progress
The script displays real-time progress:
- Current configuration (e.g., "Phase 1: SHA256 - No protections")
- Current attack being executed
- Success/failure status
- Elapsed time and estimated remaining time

## Output

Results are saved to `results/experiments/`:

### Summary CSV (`experiment_summary_TIMESTAMP.csv`)
One row per experiment with columns:
- `experiment_id` - Sequential ID
- `phase` - Phase 1 or 2
- `config_description` - Human-readable config
- `hash_mode` - SHA256, BCRYPT, or ARGON2ID
- `rate_limit`, `lockout`, `captcha`, `pepper`, `totp` - Boolean flags
- `attack_type` - brute_force or password_spraying
- `target` - Target username or group
- `target_category` - weak, medium, strong, or group
- `success` - Whether attack succeeded
- `total_attempts` - Number of login attempts made
- `time_to_crack` - Seconds to crack (if successful)
- `total_time_seconds` - Total attack duration
- `avg_latency_ms` - Average request latency
- `attempts_per_second` - Attack throughput

### Log File (`experiment_log_TIMESTAMP.txt`)
Detailed execution log with:
- Configuration transitions
- Server start/stop events
- Attack results
- Errors and warnings

### Individual Attack Results
Each attack also generates individual JSON and CSV files in `results/`:
- `{attack_type}_{target}_{hash}_{protections}_{timestamp}.json`
- `{attack_type}_{target}_{hash}_{protections}_{timestamp}.csv`

## Estimated Runtime

- **Without RATE_LIMIT/LOCKOUT**: ~2-4 hours
  - ~464 passwords × 54 experiments = ~25,000 requests
  - Depends on hash algorithm speed (SHA256 fastest, ARGON2ID slowest)

- **With RATE_LIMIT enabled** (Phase 2): Add 4-8 hours
  - Rate limit allows 5 attempts per 60 seconds
  - Exponential backoff on 429 responses (5s, 10s, 20s)

- **With LOCKOUT enabled**: Attacks will fail after 3 attempts
  - Not recommended for data collection

## Recommendations

1. **Disable RATE_LIMIT and LOCKOUT** for initial data collection:
   ```bash
   # In .env file (runner will override these anyway):
   RATE_LIMIT=false
   LOCKOUT=false
   ```

2. **Run overnight or during off-hours** - Full suite takes several hours

3. **Monitor disk space** - Generates ~100+ result files

4. **Check test_setup.py first** - Validates configuration before long run

5. **Resume capability** - If interrupted, you can modify `run_all.py` to skip completed configs

## Troubleshooting

### Server won't start
- Check if port 8001 is in use: `lsof -i :8001`
- Kill existing processes: `pkill -f uvicorn`

### Import errors
- Ensure you're running from project root
- Check virtual environment is activated

### Password list issues
- Verify `data/common_passwords.txt` exists
- Run `test_setup.py` to validate

### Rate limiting slowing down tests
- Disable RATE_LIMIT in .env before running
- Or modify protection configs in `run_all.py`

## Next Steps

After experiments complete:
1. Analyze `experiment_summary_*.csv` to compare configurations
2. Generate graphs and charts for report
3. Calculate statistics:
   - Success rate by hash algorithm
   - Average time-to-crack by protection mechanism
   - Impact of each protection on attack success
4. Write research report with findings
