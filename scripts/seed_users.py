import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.database import SessionLocal, engine
from src.models import Base, User
from src.security_manager import register_user

Base.metadata.create_all(bind=engine)


def load_users_from_json(filepath: str) -> dict:
    with open(filepath, "r") as f:
        return json.load(f)


def seed_users():
    data = load_users_from_json("data/users.json")
    db = SessionLocal()

    print(f"Seeding {len(data['users'])} users (GROUP_SEED: {data['group_seed']})")
    print("-" * 50)

    created = 0
    skipped = 0

    for user_data in data["users"]:
        username = user_data["username"]
        password = user_data["password"]
        category = user_data["category"]
        totp_secret = user_data.get("totp_secret")

        existing = db.query(User).filter(User.username == username).first()
        if existing:
            print(f"  SKIP: {username} (already exists)")
            skipped += 1
            continue

        try:
            register_user(username, password, db, totp_secret=totp_secret)
            print(f"  OK: {username} [{category}]")
            created += 1
        except Exception as e:
            print(f"  ERROR: {username} - {e}")

    db.close()

    print("-" * 50)
    print(f"Created: {created}, Skipped: {skipped}")


if __name__ == "__main__":
    seed_users()

