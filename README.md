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
├── src/                   # Application logic
│   ├── config.py         # Configuration and toggles
│   ├── database.py       # SQLAlchemy database setup
│   ├── models.py         # Database models
│   ├── auth_utils.py     # Authentication utilities
│   └── main.py           # FastAPI application
└── tests/                 # Attack simulation scripts
    └── test_attacks.py   # Brute-force and password spraying tests
```

## Features

### Hash Modes
- SHA256
- BCRYPT
- ARGON2ID

### Protection Mechanisms
- RATE_LIMIT
- LOCKOUT
- CAPTCHA
- PEPPER

## Test Users

This project requires 30 test users for comprehensive security testing.

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
- `GET /admin/get_captcha_token` - Get CAPTCHA token

## Testing

Run attack simulations:
```bash
python tests/test_attacks.py
```

