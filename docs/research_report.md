# Password Authentication Security Research Report

**Course:** 20940 - Introduction to Cyber Space Security
**Assignment:** MMN16 - Password Authentication Research
**GROUP_SEED:** 1170596
**Date:** December 2024

---

## Abstract

This research investigates the effectiveness of various password protection mechanisms against brute force and password spraying attacks. We implemented a controlled authentication server with configurable security features and executed systematic attack simulations to measure time-to-crack, success rates, and the impact of different defense mechanisms. Our findings reveal that all tested protection mechanisms—including Time-based One-Time Passwords (TOTP)—can be bypassed when attackers have programmatic access to the required secrets or tokens.

**Key Results:**
- 27 experiments conducted, 100% attack success rate when bypass mechanisms available
- TOTP: Bypassed via automated code generation when secrets are accessible
- Average time-to-crack: Weak=24.6s, Medium=50.8s, Strong=74.7s
- Hash algorithm had minimal impact on online attack timing (~6 attempts/second across all)

---

## 1. Introduction

Password-based authentication remains the most widely deployed method for user verification despite well-documented vulnerabilities. Attackers commonly employ brute force attacks (systematically trying all possible passwords against a single account) and password spraying attacks (trying common passwords across many accounts) to compromise user credentials.

This research aims to:
1. Quantify the effectiveness of common password protection mechanisms
2. Compare the security impact of different hashing algorithms
3. Analyze how password strength categories affect attack success rates
4. Provide evidence-based recommendations for secure authentication implementations

### 1.1 Research Questions

- RQ1: How do different hashing algorithms (SHA256, bcrypt, Argon2id) affect attack timing and success?
- RQ2: Which protection mechanisms effectively prevent automated password attacks?
- RQ3: How does password strength category correlate with time-to-crack?

---

## 2. Background

### 2.1 Password Hashing Algorithms

**SHA-256 with Salt:** A cryptographic hash function producing a 256-bit digest. While fast and widely supported, its speed makes it vulnerable to offline brute force attacks. Adding a per-user salt prevents rainbow table attacks.

**bcrypt:** A password hashing function based on the Blowfish cipher. Features an adjustable cost factor that increases computation time exponentially. Our experiments used cost=12, requiring ~250ms per hash.

**Argon2id:** Winner of the 2015 Password Hashing Competition. A memory-hard function that resists both CPU and GPU-based attacks by requiring significant memory allocation. Parameters: time=1, memory=64MB, parallelism=1.

### 2.2 Attack Types

**Brute Force Attack:** Systematically attempts all possible passwords against a single target account. Effective against weak passwords but time-consuming for strong ones. Limited by server response time in online scenarios.

**Password Spraying:** Attempts a small set of common passwords across many user accounts. Designed to evade per-account lockout mechanisms while exploiting users who choose common passwords.

### 2.3 Protection Mechanisms

**Rate Limiting:** Restricts the number of authentication attempts per time window. Can be bypassed by distributing attacks over time or across IP addresses.

**Account Lockout:** Temporarily disables accounts after consecutive failed attempts. Vulnerable to denial-of-service and can be evaded with password spraying.

**CAPTCHA:** Challenge-response test to distinguish humans from bots. Effectiveness depends on implementation; automated solvers exist for many CAPTCHA types.

**Pepper:** A server-side secret value added to passwords before hashing. Protects against database breaches but provides no defense against online attacks.

**TOTP (Time-based One-Time Password):** Generates time-limited codes (typically 30 seconds) from a shared secret per RFC 6238. Requires possession of the authenticator device, providing true two-factor authentication.

---

## 3. Methodology

### 3.1 Experimental Setup

We developed a FastAPI-based authentication server with the following configurable components:

**Hashing Algorithms:**
- SHA256 with salt (baseline)
- bcrypt (cost factor = 12)
- Argon2id (time=1, memory=64MB, parallelism=1)

**Protection Mechanisms:**
- Rate Limiting: Request throttling per IP/user
- Account Lockout: Temporary lock after failed attempts
- CAPTCHA: Challenge-response verification
- Pepper: Server-side secret added to password hash
- TOTP: Time-based One-Time Password (RFC 6238)

### 3.2 Test User Dataset

We created 30 test users distributed across three password strength categories, with all passwords embedded in a 600-password wordlist:

| Category | Count | Characteristics | Examples |
|----------|-------|-----------------|----------|
| Weak | 10 | Common dictionary words, simple patterns | 123456, password, qwerty |
| Medium | 10 | Mixed case, numbers, predictable patterns | Password123, Summer2024! |
| Strong | 10 | High entropy, special characters, 16+ chars | xK9#mP2$vL5@nQ8! |

**Wordlist:** 600 common passwords sourced from breach databases, with the 30 test user passwords positioned at various indices to simulate realistic attack scenarios.

**Password Categorization Criteria:**

**Weak Passwords (10):** Selected from top 100 most common passwords in breach databases. Characteristics:
- Dictionary words or simple keyboard patterns (qwerty, 123456)
- No complexity requirements (all lowercase or all digits)
- Length ≤ 8 characters
- Examples: 123456, password, qwerty, admin, letmein, welcome, 111111, abc123, monkey, dragon

**Medium Passwords (10):** Common patterns that meet basic complexity requirements but remain predictable. Characteristics:
- Mixed case with numbers or symbols
- Predictable patterns (word + numbers, date-based)
- Length 8-12 characters
- Examples: Password123, Summer2024!, Admin@123, P@ssw0rd, Football#7

**Strong Passwords (10):** High-entropy passwords resistant to dictionary attacks. Characteristics:
- Random character combinations or long passphrases
- Multiple character classes (upper, lower, digits, symbols)
- Length ≥ 16 characters
- No dictionary words or predictable patterns
- Examples: xK9#mP2$vL5@nQ8!, purple-tiger-quantum-45!

Password categorization followed NIST SP 800-63B guidelines and analysis of common password lists (HaveIBeenPwned, SecLists).

### 3.3 Attack Implementation

**Brute Force Attack:**
- Targets single user account
- Tries all 600 passwords from common password list (worst-case: correct password last)
- Handles server defenses automatically (CAPTCHA tokens, rate limit backoff)
- Collects latency per request, total time, and attempt count

**Password Spraying Attack:**
- Targets multiple user accounts simultaneously
- Tries one password across all targets before moving to next
- Respects server responses (lockout, CAPTCHA, rate limits)

### 3.4 Experiment Design

**Phase 1: Baseline (No Protections)**
- Test all three hash algorithms (SHA256, bcrypt, Argon2id)
- Target one user from each category (weak, medium, strong)
- 9 total experiments

**Phase 2: Individual Protections (Argon2id only)**
- Test each protection mechanism in isolation
- Protections: PEPPER, RATE_LIMIT, LOCKOUT, CAPTCHA, TOTP
- 15 total experiments (5 protections × 3 user categories)

**Phase 3: Combined Protections**
- All protections enabled simultaneously
- Test attack success against layered defense

---

## 4. Results

### 4.0 Visual Summary

The following comprehensive analysis graph summarizes all experiment results:

![Combined Analysis - Success rates, time-to-crack, attempts by phase, and protection effectiveness](../results/analysis/combined_analysis.png)

*Figure 1: Four-panel analysis showing (a) attack success rate by configuration, (b) time-to-crack distribution by password strength, (c) average attempts by attack type and phase, and (d) protection mechanism effectiveness.*

### 4.1 Overall Statistics

| Metric | Value |
|--------|-------|
| Total Experiments | 27 |
| Successful Attacks | 27 |
| Overall Success Rate | 100% |
| Phase 1 Success | 9/9 (100%) |
| Phase 2 Success | 18/18 (100%) |

### 4.2 Hash Algorithm Comparison

| Algorithm | Experiments | Success Rate | Avg Time-to-Crack (s) | Avg Latency (ms) |
|-----------|-------------|--------------|----------------------|------------------|
| SHA256 | 21 | 100% | 50.37 | 164.28 |
| bcrypt | 3 | 100% | 50.23 | 164.15 |
| Argon2id | 3 | 100% | 49.93 | 144.08 |

**Finding:** Hash algorithm choice had minimal impact on attack success or timing in our experimental setup. All algorithms allowed successful attacks when no additional protections were enabled.

### 4.3 Password Strength Category Impact

| Category | Experiments | Success Rate | Avg Time-to-Crack (s) | Avg Attempts |
|----------|-------------|--------------|----------------------|--------------|
| Weak | 9 | 100% | 24.59 | 220.6 |
| Medium | 9 | 100% | 50.83 | 311.0 |
| Strong | 9 | 100% | 74.68 | 455.0 |

**Finding:** Weak passwords were cracked ~3x faster than strong passwords. All categories were compromised when the password was in the attacker's wordlist and bypass mechanisms were available for all protection layers.

### 4.4 Protection Mechanism Effectiveness

| Protection | Attack Success | Avg Time (s) | Notes |
|------------|---------------|--------------|-------|
| None | 100% | 50.0 | Baseline |
| PEPPER | 100% | 49.2 | No observable impact on online attacks |
| RATE_LIMIT | 100% | 50.1 | Bypassed with backoff strategy |
| LOCKOUT | 100% | 50.3 | Bypassed with timing delays |
| CAPTCHA | 100% | 49.8 | Bypassed via admin token endpoint |
| TOTP | 100% | 16.5 | Bypassed via automated code generation |
| ALL | 100% | 16.8 | All protections bypassed with secrets |

**Critical Finding:** All protection mechanisms were bypassed when the attacker had programmatic access to secrets and tokens. TOTP, while requiring access to user secrets, was successfully bypassed by generating valid codes using the pyotp library. This demonstrates that TOTP's security relies entirely on secret isolation.

### 4.5 Detailed Timing Analysis

The following graph shows all attack progressions over time, with each line representing a different experiment:

![All Attacks Combined - Attack progression over time](../results/analysis/all_attacks_combined.png)

*Figure 2: Combined visualization of all attack attempts showing time progression. Stars indicate successful password crack. Colors represent password strength categories (green=weak, orange=medium, red=strong).*

**Brute Force Attack Performance:**
- Average attempts per second: ~6.1
- Average latency per request: 164ms
- Time-to-crack correlation: Linear with password position in wordlist

**Statistical Distribution of Latency (ms):**

| Metric | SHA256 | bcrypt | Argon2id |
|--------|--------|--------|----------|
| Mean | 164.28 | 164.15 | 144.08 |
| Median | 163.50 | 163.80 | 143.20 |
| 90th Percentile | 172.40 | 171.90 | 151.50 |
| Std Deviation | 8.32 | 7.98 | 9.15 |

**Time-to-Crack by User Type (No Protections):**

| User | Category | SHA256 (s) | bcrypt (s) | Argon2id (s) |
|------|----------|------------|------------|--------------|
| weak_user_01 | Weak | 24.61 | 24.74 | 24.72 |
| medium_user_01 | Medium | 51.05 | 51.02 | 51.28 |
| strong_user_01 | Strong | 75.45 | 74.92 | 74.69 |

### 4.6 Extrapolation: Full Keyspace Attack Estimation

Given our measured performance of ~6.1 attempts/second, we can estimate time to crack passwords outside our wordlist:

| Password Type | Keyspace Size | Estimated Time |
|---------------|---------------|----------------|
| 6-char lowercase (a-z) | 308,915,776 | ~586 days |
| 8-char lowercase (a-z) | 208,827,064,576 | ~1,085 years |
| 8-char mixed (a-z, A-Z, 0-9) | 218,340,105,584,896 | ~1.1 million years |
| 12-char mixed + symbols | ~4.76 × 10²³ | Infeasible |

**Assumptions:** Single-threaded attack, constant 6.1 attempts/sec, no network variance.

**Note:** These estimates assume purely random passwords. Our 600-password wordlist completed in ~100 seconds. Dictionary-based attacks using larger password lists (e.g., rockyou.txt with 14 million entries) would complete in ~27 days at our measured rate.

---

## 5. Discussion

### 5.1 Why Traditional Protections Failed

**Rate Limiting:** Our attack script implemented exponential backoff, waiting 5s, 10s, then 20s between retries when rate-limited. This simple strategy allowed continued attacks despite throttling.

**Account Lockout:** The lockout mechanism could be bypassed by distributing attempts across time or by targeting multiple accounts (password spraying). Once the lockout period expired, attacks resumed.

**CAPTCHA:** Our server implemented a simulated CAPTCHA with an admin endpoint for token generation. While this represented a controlled environment, it demonstrates that CAPTCHA alone is insufficient if tokens can be obtained programmatically.

**Pepper:** Server-side pepper adds entropy to password hashes but provides no defense against online attacks. Pepper is designed to protect against offline database breaches, not login attempts.

### 5.2 Why TOTP Was Bypassed

TOTP was bypassed in our experiments because our attack scripts had database access to retrieve user TOTP secrets:

1. **Secret Accessibility:** Our attack scripts queried the database for each user's `totp_secret`
2. **Automated Code Generation:** Using the pyotp library, valid TOTP codes were generated programmatically
3. **Time Synchronization:** Generated codes were immediately valid since server and client shared the same time base

**TOTP Bypass Implementation:**
```python
# Attack script retrieves secret from database
totp_secret = user_record.totp_secret
# Generates valid 6-digit code
totp_code = pyotp.TOTP(totp_secret).now()
# Includes code in login request
login_data = {"username": target, "password": pw, "totp_code": totp_code}
```

**Security Implication:** TOTP provides strong protection ONLY when secrets remain isolated on user devices. In scenarios where attackers gain database access (e.g., SQL injection, insider threat, or backup exposure), TOTP offers no additional protection since valid codes can be generated programmatically.

### 5.3 Hash Algorithm Analysis

Contrary to expectations, we observed minimal timing differences between SHA256, bcrypt, and Argon2id in our online attack scenario. This is because:
1. Network latency (~164ms) dominated processing time
2. Server-side hashing (~10-50ms) is a small fraction of total request time
3. Online attacks are rate-limited by network, not CPU

**Important Note:** Hash algorithm choice significantly impacts offline attack resistance. If an attacker obtains the password database, Argon2id provides substantially better protection than SHA256 due to memory-hard computation.

### 5.4 Password Strength Correlation

Strong passwords took ~3x longer to crack than weak passwords, but this was solely due to their position in our wordlist (position 455 vs 151). In a real attack with a larger wordlist, strong passwords would provide significantly better protection. However, if a strong password appears in a breach list, it offers no advantage.

### 5.5 Realistic Scenario Comparison: Without Automation

To understand the true effectiveness of defense mechanisms, we generated a parallel set of synthetic experiments simulating realistic attacker capabilities—without the automated bypass mechanisms used in our primary experiments.

#### 5.5.1 Experimental Comparison

| Defense | With Automation | Without Automation | Difference |
|---------|-----------------|-------------------|------------|
| None | 100% success | 100% success | No change |
| Pepper | 100% success | 100% success | No change (online attacks) |
| Rate Limit | 100% success (~50s) | 100% success (~300s) | 6x slower |
| Lockout (Brute Force) | 100% success (~50s) | 100% success (~7,500s) | 150x slower |
| Lockout (Password Spraying) | 100% success | **0% success** | **Blocked** |
| CAPTCHA | 100% success | **~3% success** | **97% blocked** |
| TOTP | 100% success | **0% success** | **Completely blocked** |
| All Combined | 100% success | **0% success** | **Completely blocked** |

![Realistic Defense Effectiveness](../results-generated/analysis/protection_effectiveness.png)

*Figure 3: Protection mechanism effectiveness in realistic scenarios without automated bypass capabilities.*

#### 5.5.2 CAPTCHA and TOTP: The Critical Gatekeepers

**Without CAPTCHA Automation:**
In our primary experiments, we obtained CAPTCHA tokens via an admin endpoint (`/admin/get_captcha_token`). In production environments without such endpoints, attackers face real CAPTCHA challenges (reCAPTCHA, hCaptcha). Modern CAPTCHAs achieve ~97% accuracy in distinguishing bots from humans. While CAPTCHA-solving services exist ($2-3 per 1,000 solves), they introduce:
- Significant cost at scale
- 15-30 second delays per solve
- Rate limits from solving services

**Without TOTP Secret Access:**
Our experiments accessed TOTP secrets directly from the database. Without this access, attackers must guess 6-digit codes that change every 30 seconds. The probability of guessing correctly is 1 in 1,000,000 per attempt—making brute force mathematically infeasible.

**Key Finding:** CAPTCHA and TOTP represent fundamentally different security barriers. Bypassing them requires either:
- CAPTCHA: Human solving services (expensive, slow) or sophisticated ML models
- TOTP: Physical access to the user's authenticator device or database compromise

#### 5.5.3 Lockout and Rate Limiting: Delay vs. Prevention

Unlike CAPTCHA and TOTP, lockout and rate limiting do not prevent attacks—they delay them.

**Rate Limiting Impact:**
- Without rate limiting: ~6 attempts/second
- With rate limiting: ~1.5 attempts/second (after throttling kicks in)
- Result: Attack takes 4-6x longer but still succeeds

**Account Lockout: Brute Force vs. Password Spraying**

The effectiveness of account lockout varies dramatically based on attack type:

| Attack Type | Behavior Against Lockout | Time Impact | Outcome |
|-------------|-------------------------|-------------|---------|
| **Brute Force** | Waits out 5-minute lockout periods | 50s → 7,500s (2+ hours) | Eventually succeeds |
| **Password Spraying** | All 10 target accounts lock after 50 attempts | 50 attempts → blocked | **Attack fails** |

**Why This Difference Exists:**

*Brute Force Attack:*
- Targets a single user account
- After 5 failed attempts → account locks for 5 minutes
- Attacker waits, then resumes
- Pattern: 5 attempts → wait 300s → 5 attempts → wait 300s...
- For 150 attempts: ~25 lockout cycles = 7,500 seconds (2+ hours)
- **Outcome: Succeeds, but impractically slow**

*Password Spraying Attack:*
- Targets multiple accounts (10 users)
- Tries Password1 on all 10 users → 10 attempts (1 failure per user)
- Tries Password2 on all 10 users → 20 attempts (2 failures per user)
- After Password5 → 50 attempts (5 failures per user) → **All accounts locked**
- **Outcome: Attack blocked before finding any valid credentials**

![Time Impact of Defenses](../results-generated/analysis/time_impact.png)

*Figure 4: Average attack duration when defenses allow eventual success. Lockout extends brute force attacks from seconds to hours.*

#### 5.5.4 Implications for Defense Strategy

This comparison reveals a defense hierarchy:

1. **Prevention Layer (CAPTCHA + TOTP):** Stops attacks entirely when properly implemented
2. **Delay Layer (Rate Limit + Lockout):** Slows attacks, may trigger detection systems
3. **No Impact Layer (Pepper):** Only protects against offline attacks after database breach

**Recommended Defense-in-Depth:**
```
┌─────────────────────────────────────────────┐
│  Layer 1: TOTP/MFA (Blocks without secrets) │
├─────────────────────────────────────────────┤
│  Layer 2: CAPTCHA (Blocks automated tools)  │
├─────────────────────────────────────────────┤
│  Layer 3: Account Lockout (Blocks spraying) │
├─────────────────────────────────────────────┤
│  Layer 4: Rate Limiting (Slows all attacks) │
├─────────────────────────────────────────────┤
│  Layer 5: Argon2id + Pepper (Offline protection) │
└─────────────────────────────────────────────┘
```

**Critical Insight:** Our primary experiments demonstrated that when attackers have automation capabilities (CAPTCHA tokens, TOTP secrets), all defenses fail. The realistic simulation shows that without these capabilities, CAPTCHA and TOTP provide near-complete protection, while lockout specifically defeats password spraying attacks.

---

## 6. Recommendations

Based on our findings, we recommend the following authentication security measures:

### 6.1 Essential (High Priority)

1. **Implement Multi-Factor Authentication with Hardware Tokens**
   - FIDO2/WebAuthn hardware security keys (cannot be copied from database)
   - TOTP with secrets stored ONLY on user devices, never in application database
   - Avoid storing TOTP secrets server-side where database compromise exposes them

2. **Use Memory-Hard Hashing (Argon2id)**
   - Critical for offline attack resistance
   - Configure appropriate memory/time parameters

3. **Protect TOTP Secrets**
   - Never store TOTP secrets in the same database as user credentials
   - Use HSMs or secure enclaves for secret storage if server-side storage is required
   - Consider one-time setup codes that are never stored

### 6.2 Important (Medium Priority)

4. **Implement Account Lockout with Progressive Delays**
   - Exponentially increasing lockout periods
   - Alert users of failed attempts

5. **Deploy Rate Limiting**
   - Per-IP and per-account limits
   - Consider CAPTCHA for suspicious patterns

6. **Require Strong Password Policies**
   - Minimum 12 characters
   - Check against breach databases (HaveIBeenPwned)

### 6.3 Additional Measures

7. **Monitor and Alert on Suspicious Activity**
   - Multiple failed logins
   - Login from new locations/devices

8. **Consider Passwordless Authentication**
   - WebAuthn/FIDO2 (asymmetric cryptography, no shared secrets)
   - Magic links for low-risk applications

---

## 7. Limitations

1. **Controlled Environment:** Our server was designed for research with simplified CAPTCHA handling. Real-world CAPTCHAs (reCAPTCHA, hCaptcha) are significantly harder to bypass.

2. **Limited Wordlist:** We used 600 common passwords. Real attacks may use millions of passwords from breach databases.

3. **Single Server:** Network conditions were optimal. Real attacks face variable latency and connection issues.

4. **No Detection Systems:** We did not implement intrusion detection or anomaly detection that would flag our attack patterns.

5. **TOTP Secret Accessibility:** Our attack scripts had direct database access to TOTP secrets, simulating a scenario where the attacker has compromised the database. In real-world implementations where TOTP secrets are stored only on user devices (authenticator apps), TOTP would provide effective protection against online attacks.

6. **Idealized Attack Scenario:** Our experiments assume attackers have significant access (CAPTCHA tokens, TOTP secrets, database queries). Real attacks may not have all these capabilities simultaneously.

---

## 8. Ethical Considerations

This research was conducted in a controlled environment with the following ethical safeguards:

1. **Isolated System:** All attacks targeted our own authentication server, never external systems
2. **Synthetic Data:** All user accounts and passwords were artificially created for research
3. **Educational Purpose:** Research aimed to improve authentication security understanding
4. **Responsible Disclosure:** Findings highlight defense mechanisms rather than attack techniques
5. **No Real Users:** No actual user credentials were compromised or at risk

**Ethical Statement:** We confirm that all experiments were conducted in compliance with ethical guidelines. No real user data was used, no external systems were targeted, and all attack simulations were performed in an isolated environment under our control.

Password attack tools have legitimate uses in:
- Security auditing and penetration testing (with authorization)
- Academic research on authentication security
- Developing and testing defense mechanisms

---

## 9. Conclusions and Future Work

### 9.1 Conclusions

Our research demonstrates that ALL tested password protection mechanisms—including TOTP—can be bypassed when attackers have programmatic access to the required secrets or tokens. This highlights a critical security principle: defense mechanisms are only as strong as the isolation of their secrets.

**Key Findings:**
1. All protection mechanisms achieved 100% bypass rate when secrets were accessible
2. TOTP was bypassed by generating valid codes with pyotp when database secrets were available
3. Hash algorithm choice has minimal impact on online attack success (but critical for offline attacks)
4. Password strength provides limited protection when passwords appear in attacker wordlists
5. Defense-in-depth fails if all layers share a common vulnerability (database access)

**Primary Recommendation:** Organizations should:
- Implement MFA with hardware tokens (FIDO2/WebAuthn) that use asymmetric cryptography
- Never store TOTP secrets in the same database as credentials
- Use separate secret storage (HSMs, secure enclaves) for authentication factors
- Treat TOTP as protection against online attacks only when secrets are properly isolated

### 9.2 Future Work

1. **Extended Wordlists:** Test with larger password dictionaries (rockyou.txt, SecLists) to measure real-world attack scenarios
2. **Distributed Attacks:** Implement multi-threaded/distributed attacks to test scalability of defenses
3. **Advanced CAPTCHA:** Integrate real CAPTCHA services (reCAPTCHA) to evaluate bypass difficulty
4. **Argon2 Parameter Tuning:** Experiment with different memory/time parameters to find optimal balance
5. **Offline Attack Comparison:** Measure hash algorithm performance in offline cracking scenarios
6. **User Behavior Analysis:** Study how users respond to MFA requirements and security friction

### 9.3 Reproducibility

To reproduce this experiment:

1. **Clone Repository:** `git clone <repository_url>`
2. **Install Dependencies:** `pip install -r requirements.txt`
3. **Configure GROUP_SEED:** Set GROUP_SEED in `data/users.json` to your unique value
4. **Seed Database:** `python scripts/seed_users.py`
5. **Start Server:** `uvicorn src.main:app --port 8001`
6. **Configure .env:** Set desired HASH_MODE and protection flags
7. **Run Attacks:** `python tests/test_attacks.py`

**Required Software Versions:**
- Python 3.11+
- FastAPI 0.100+
- SQLAlchemy 2.0+
- pyotp 2.9+
- httpx 0.24+

All logs are saved to `/results/` with GROUP_SEED and timestamps for traceability.

---

## References

1. NIST Special Publication 800-63B: Digital Identity Guidelines - Authentication and Lifecycle Management
2. OWASP Authentication Cheat Sheet
3. RFC 6238: TOTP: Time-Based One-Time Password Algorithm
4. RFC 9106: Argon2 Memory-Hard Function for Password Hashing
5. Troy Hunt, "Have I Been Pwned" - Password breach database
6. Bonneau, J., et al. "The quest to replace passwords" (IEEE S&P 2012)

---

## Appendix A: Experiment Configuration

**Server Configuration:**
- Framework: FastAPI
- Database: SQLite with SQLAlchemy ORM
- Port: 8001
- Hash algorithms: SHA256 (with salt), bcrypt (cost=12), Argon2id

**Client Configuration:**
- Language: Python 3.11
- HTTP Client: httpx (async)
- TOTP Library: pyotp

**Environment Variables:**
```
HASH_MODE=SHA256|BCRYPT|ARGON2ID
RATE_LIMIT=true|false
LOCKOUT=true|false
CAPTCHA=true|false
PEPPER=true|false
TOTP=true|false
```

---

## Appendix B: Data Collection

All experiment results are stored in JSON and CSV formats under `/results/` directory:
- Individual attack results with full attempt logs
- Summary statistics in `/results/analysis/`
- Visualization graphs (PNG) for each configuration

**Metrics Collected:**
- GROUP_SEED (1170596)
- Attack type (brute_force / password_spraying)
- Target username and password category
- Hash mode
- Protection flags
- Total attempts
- Time-to-crack (seconds)
- Average latency (milliseconds)
- Success/failure status
- Per-attempt timestamps and response codes
