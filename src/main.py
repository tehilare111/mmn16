from fastapi import FastAPI
from src.database import engine
from src.models import Base
from src.middleware import LoginLoggerMiddleware

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(LoginLoggerMiddleware)


@app.post("/register")
async def register():
    pass


@app.post("/login")
async def login():
    pass


@app.post("/login_totp")
async def login_totp():
    pass


@app.get("/admin/get_captcha_token")
async def get_captcha_token():
    pass
