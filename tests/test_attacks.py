import httpx
import asyncio

BASE_URL = "http://localhost:8000"


async def brute_force_attack():
    pass


async def password_spraying_attack():
    pass


async def main():
    async with httpx.AsyncClient() as client:
        await brute_force_attack()
        await password_spraying_attack()


if __name__ == "__main__":
    asyncio.run(main())
