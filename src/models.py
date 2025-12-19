from sqlalchemy import Column, Integer, String
from src.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    salt = Column(String, nullable=True)
    totp_secret = Column(String, nullable=True)
    failed_attempts = Column(Integer, default=0)
