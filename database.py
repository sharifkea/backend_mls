# database.py (clean & secure version)
import asyncpg
from contextlib import asynccontextmanager
import os
from dotenv import load_dotenv

load_dotenv()  # loads .env file

class Database:
    def __init__(self):
        # Get DSN from environment — no fallback
        self.dsn = os.getenv("DATABASE_URL")
        
        if not self.dsn:
            raise ValueError(
                "DATABASE_URL not found in environment variables. "
                "Please set it in .env file or system environment."
            )
            
        self.pool: asyncpg.Pool | None = None

    async def connect(self):
        if self.pool is None:
            self.pool = await asyncpg.create_pool(self.dsn)
            print("Database pool connected")

    async def close(self):
        if self.pool:
            await self.pool.close()
            print("Database pool closed")

    @asynccontextmanager
    async def connection(self):
        if self.pool is None:
            raise RuntimeError("Database not connected. Call await db.connect() first.")
        async with self.pool.acquire() as conn:
            yield conn


# Create and export the instance
db = Database()