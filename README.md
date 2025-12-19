# FastAPI Auth Research Server

A professional FastAPI research server project designed for authentication security research and attack simulation.

## Configuration

- **GROUP_SEED**: 1170596

## Project Structure

```
.
├── .env                    # Environment variables
├── README.md              # Project documentation
├── attempts.log           # Authentication attempt logs
├── data/
│   └── users.json         # Test user dataset (30 accounts)
├── scripts/
│   └── seed_users.py      # Database seeding script
├── src/                   # Application logic
│   ├── config.py         # Configuration and toggles
│   ├── database.py       # SQLAlchemy database setup
│   ├── models.py         # Database models
│   ├── schemas.py        # Pydantic request/response models
│   ├── exceptions.py     # Custom domain exceptions
│   ├── security_manager.py # Authentication business logic
│   ├── auth_utils.py     # Password hashing utilities
│   ├── middleware.py     # Request logging middleware
│   └── main.py           # FastAPI application
└── tests/                 # Attack simulation scripts
    └── test_attacks.py   # Brute-force and password spraying tests
```

## Features

### Hash Modes
- SHA256 (with per-user salt)
- BCRYPT (cost = 12)
- ARGON2ID (time = 1, memory = 64MB, parallelism = 1)

### Protection Mechanisms
- RATE_LIMIT - Limits login attempts per user (5 attempts / 60 seconds)
- LOCKOUT - Locks account after 3 failed attempts
- CAPTCHA - Requires CAPTCHA token for login
- PEPPER - Adds server-side secret to passwords before hashing

## Test Users Dataset

This project includes 30 test accounts for security research, divided into three categories based on password strength.

### Seeding the Database

```bash
python scripts/seed_users.py
```

### Password Classification Criteria

#### Weak Passwords (10 accounts)

Passwords classified as **weak** meet one or more of the following criteria:
- Appear in common password breach databases (e.g., rockyou.txt)
- Are dictionary words without modifications
- Use simple keyboard patterns (e.g., qwerty, 123456)
- Are shorter than 8 characters
- Contain only one character class (letters only or numbers only)

| Username | Password | Classification Reason |
|----------|----------|----------------------|
| weak_user_01 | 123456 | Most common password worldwide, purely numeric, only 6 characters |
| weak_user_02 | password | Dictionary word, appears in top 10 most common passwords |
| weak_user_03 | qwerty | Keyboard pattern, extremely common, only 6 characters |
| weak_user_04 | admin | Common default credential, dictionary word, only 5 characters |
| weak_user_05 | letmein | Common phrase, appears in password breach databases |
| weak_user_06 | welcome | Dictionary word, commonly used as default password |
| weak_user_07 | 111111 | Repeated single digit, no complexity, easily guessable |
| weak_user_08 | abc123 | Simple sequential pattern, very common combination |
| weak_user_09 | monkey | Common word, appears in top 25 most used passwords |
| weak_user_10 | dragon | Common word, frequently found in password breach lists |

#### Medium Passwords (10 accounts)

Passwords classified as **medium** meet typical password policy requirements but have predictable patterns:
- Dictionary word with common modifications (capitalization, number suffix)
- Predictable patterns (word + year, name + numbers)
- Common leetspeak substitutions (@ for a, 0 for o)
- 8-12 characters with limited character class diversity

| Username | Password | Classification Reason |
|----------|----------|----------------------|
| medium_user_01 | Password123 | Common word with predictable capitalization and number suffix |
| medium_user_02 | Summer2024! | Seasonal word + year + symbol, predictable pattern |
| medium_user_03 | Admin@123 | Common word with symbol and numbers, follows typical policy pattern |
| medium_user_04 | Qwerty123! | Keyboard pattern with complexity additions, still predictable |
| medium_user_05 | Welcome1! | Dictionary word meeting minimum complexity requirements |
| medium_user_06 | P@ssw0rd | Common leetspeak substitution, well-known pattern |
| medium_user_07 | Sunshine99 | Common word with numbers, no special characters |
| medium_user_08 | Michael1985 | Name + year pattern, vulnerable to targeted attacks |
| medium_user_09 | Football#7 | Common interest word with symbol and number |
| medium_user_10 | January2024 | Month + year pattern, predictable temporal password |

#### Strong Passwords (10 accounts)

Passwords classified as **strong** exhibit high entropy and resistance to attacks:
- 16+ characters in length
- Random or pseudo-random character sequences
- All four character classes (uppercase, lowercase, numbers, symbols)
- No recognizable patterns or dictionary words
- Passphrases with unrelated words and random elements

| Username | Password | Classification Reason |
|----------|----------|----------------------|
| strong_user_01 | xK9#mP2$vL5@nQ8! | 16 chars, random mix of upper/lower/numbers/symbols, no patterns |
| strong_user_02 | Tr0ub4dor&3#Horse | 17 chars, mixed case, numbers, symbols, no dictionary words |
| strong_user_03 | 7Gh$kL9@mNpQ2#xZ | 16 chars, cryptographically random appearance, high entropy |
| strong_user_04 | Bv8*Wx3!Yz6@Qr1# | 16 chars, alternating character types, no recognizable patterns |
| strong_user_05 | purple-tiger-quantum-45! | 24 chars passphrase, unrelated words, includes number and symbol |
| strong_user_06 | Jf9$Kp2@Lm5#Nq8!Rv | 18 chars, random sequence, maximum character class diversity |
| strong_user_07 | crystal-moon-delta-99#X | 23 chars passphrase with random suffix, high entropy |
| strong_user_08 | Ht4@Vx7#Cz1!Wp9$Ek3 | 19 chars, no sequential patterns, all character classes |
| strong_user_09 | binary-phoenix-craft-77!Z | 25 chars passphrase, uncommon word combination, mixed suffix |
| strong_user_10 | Mq5#Yr8@Zk2!Bs6$Nv9#Pw | 22 chars, maximum complexity, cryptographically strong |

### Entropy Estimation

| Category | Avg Length | Estimated Entropy | Keyspace Size |
|----------|------------|-------------------|---------------|
| Weak | 6 chars | ~20 bits | ~10^6 |
| Medium | 10 chars | ~40 bits | ~10^12 |
| Strong | 19 chars | ~80+ bits | ~10^24+ |

## Logging

All authentication attempts to `/login` and `/login_totp` endpoints are automatically logged to `attempts.log` with the following information:
- Timestamp
- Group seed
- Username
- Hash mode
- Protection flags
- Result (success/failure)
- Latency in milliseconds

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Create `.env` file in the root directory with:
```
GROUP_SEED=1170596
PEPPER_SECRET=your_pepper_secret_here
```

3. Run the server:
```bash
uvicorn src.main:app --reload
```

The server will start at `http://localhost:8000`

- API Documentation: `http://localhost:8000/docs`
- Alternative Docs: `http://localhost:8000/redoc`

## Endpoints

- `POST /register` - User registration
- `POST /login` - Standard login
- `POST /login_totp` - TOTP-based login
- `GET /admin/get_captcha_token` - Get CAPTCHA token for automated testing
- `GET /admin/get_simulation_token` - Get simulation token to bypass rate limiting

## Testing

1. Seed the test users:
```bash
python scripts/seed_users.py
```

2. Run attack simulations:
```bash
python tests/test_attacks.py
```

## Ethical Statement

All experiments in this project are conducted on local/virtual systems owned by the researchers. No real user data is used. All test accounts use artificial credentials generated specifically for this research. No attacks are performed on external networks or systems.
