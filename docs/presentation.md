# Password Authentication Security Research
## MMN16 - Cyber Security

**GROUP_SEED: 1170596**

December 2024

---

# Research Goal

**Question:** Which password protection mechanisms effectively prevent automated attacks?

**Approach:**
- Built controlled authentication server
- Implemented brute force & password spraying attacks
- Tested 5 protection mechanisms across 3 hash algorithms
- Measured time-to-crack, success rates, latency

---

# Experimental Setup

**Authentication Server:**
- FastAPI backend
- SQLite database
- Configurable protections

**Hash Algorithms Tested:**
| Algorithm | Configuration |
|-----------|---------------|
| SHA256 | With salt |
| bcrypt | cost=12 |
| Argon2id | time=1, mem=64MB |

---

# Protection Mechanisms Tested

| Protection | Description |
|------------|-------------|
| Rate Limiting | Request throttling per IP/user |
| Account Lockout | Lock after N failed attempts |
| CAPTCHA | Challenge-response verification |
| Pepper | Server-side hash secret |
| **TOTP** | Time-based One-Time Password (RFC 6238) |

---

# Test Dataset

**30 Users across 3 categories:**

| Category | Count | Example Passwords |
|----------|-------|-------------------|
| Weak | 10 | 123456, password, qwerty |
| Medium | 10 | Password123, Summer2024! |
| Strong | 10 | xK9#mP2$vL5@nQ8! |

All passwords embedded in common_passwords.txt for controlled testing

---

# Attack Implementation

**Brute Force Attack:**
- Target single user
- Try all passwords sequentially
- Handle server defenses (backoff, CAPTCHA tokens)

**Password Spraying:**
- Target multiple users
- Try one password across all users
- Evade per-account lockout

---

# Key Result: Overall Statistics

| Metric | Value |
|--------|-------|
| Total Experiments | **23** |
| Successful Attacks | 21 |
| Overall Success Rate | **91.3%** |
| Phase 1 (No protection) | 9/9 (100%) |
| Phase 2 (With protections) | 12/14 (85.7%) |

---

# Hash Algorithm Comparison

| Algorithm | Success Rate | Avg Time-to-Crack | Avg Latency |
|-----------|--------------|-------------------|-------------|
| SHA256 | 100% | 50.37s | 164.28ms |
| bcrypt | 100% | 50.23s | 164.15ms |
| Argon2id | 88.2% | 49.93s | 144.08ms |

**Finding:** Hash algorithm had minimal impact on online attacks
(Network latency dominates server-side hashing time)

---

# Password Strength Impact

| Category | Success Rate | Avg Time-to-Crack | Avg Attempts |
|----------|--------------|-------------------|--------------|
| Weak | 77.8% | **24.6s** | 221 |
| Medium | 100% | 50.8s | 311 |
| Strong | 100% | **74.7s** | 455 |

Strong passwords took **3x longer** to crack than weak passwords

---

# Critical Finding: Protection Effectiveness

| Protection | Attack Success | Notes |
|------------|----------------|-------|
| None | 100% | Baseline |
| PEPPER | 100% | No impact on online attacks |
| RATE_LIMIT | 100% | Bypassed with backoff |
| LOCKOUT | 100% | Bypassed with timing |
| CAPTCHA | 100% | Automated token acquisition |
| **TOTP** | **0%** | **Completely blocked** |

---

# Why TOTP Succeeded

1. **Time-based expiration** - Codes valid only 30 seconds
2. **Secret requirement** - Attacker needs user's TOTP secret
3. **No bypass mechanism** - Unlike CAPTCHA, cannot request valid codes
4. **True second factor** - Requires possession of authenticator

**Even with correct password, attacks failed without TOTP secret**

---

# Why Traditional Protections Failed

**Rate Limiting:** Bypassed with exponential backoff (5s, 10s, 20s delays)

**Account Lockout:** Bypassed with password spraying or waiting for lockout expiration

**CAPTCHA:** Automated token generation (simulated environment)

**Pepper:** Only protects against offline attacks (database breaches)

---

# Timing Analysis

**Attack Performance:**
- ~6.1 attempts per second
- ~164ms average latency per request
- Linear correlation: time ∝ password position

**By User Category (No Protections):**
| User Type | Time-to-Crack |
|-----------|---------------|
| weak_user_01 | 24.7s |
| medium_user_01 | 51.1s |
| strong_user_01 | 74.7s |

---

# Extrapolation: Full Keyspace

At 6.1 attempts/second:

| Password Type | Keyspace | Time |
|---------------|----------|------|
| 6-char lowercase | 309M | ~586 days |
| 8-char lowercase | 209B | ~1,085 years |
| 8-char mixed | 218T | ~1.1M years |

**Dictionary attacks** (14M passwords) would take ~27 days

---

# Recommendations

**Essential (High Priority):**
1. Implement MFA (TOTP or hardware keys)
2. Use Argon2id for password hashing

**Important:**
3. Progressive lockout delays
4. Rate limiting (per-IP and per-account)
5. Strong password policies (12+ chars, breach checking)

---

# Conclusion

**Key Findings:**
1. TOTP was the **only** mechanism that blocked 100% of attacks
2. Hash algorithm choice: minimal impact on online attacks
3. Password strength: limited protection if password is in wordlist
4. Combined defenses without MFA remain vulnerable

**Recommendation:** Implement TOTP/MFA as primary defense

---

# Demo: Attack Execution

```bash
# Run brute force attack
python -m tests.brute_force

# Run password spraying
python -m tests.password_spraying

# Results saved to: results/
```

**Sample output logged to results/ directory with:**
- GROUP_SEED for traceability
- Per-attempt timing data
- Success/failure status

---

# Code Architecture

```
mmn16/
├── src/
│   └── main.py          # FastAPI server
├── tests/
│   ├── test_attacks.py  # Configuration
│   ├── brute_force.py   # Brute force attack
│   ├── password_spraying.py
│   ├── client.py        # HTTP client
│   └── reporting.py     # Results/metrics
├── data/
│   └── mid_common_passwords.txt
└── results/             # Experiment output
```

---

# Ethical Considerations

- All attacks on **isolated, controlled server**
- **Synthetic data** only (no real users)
- Educational/research purpose
- Findings improve defense understanding

**No external systems targeted. No real credentials compromised.**

---

# Questions?

**GROUP_SEED: 1170596**

**Results:** /results/analysis/

**Report:** /docs/research_report.md

---
