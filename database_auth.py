import asyncpg
from contextlib import asynccontextmanager
import os
from dotenv import load_dotenv

load_dotenv()  # loads .env file

class Database_auth:
    def __init__(self):
        # Get DSN from environment — no fallback
        self.dsn = os.getenv("DATABASE_URL_auth")
        
        if not self.dsn:
            raise ValueError(
                "DATABASE_URL_auth not found in environment variables. "
                "Please set it in .env file or system environment."
            )
            
        self.pool: asyncpg.Pool | None = None
        self._connected = False  # Optional: track connection state

    async def connect(self):
        """Create database connection pool"""
        if self.pool is None:
            try:
                self.pool = await asyncpg.create_pool(
                    self.dsn,
                    min_size=1,
                    max_size=10,
                    command_timeout=60
                )
                self._connected = True
                print(f"✅ Auth Database pool connected to {self.dsn.split('@')[1].split('/')[0]}")
            except Exception as e:
                print(f"❌ Failed to connect to Auth Database: {e}")
                raise

    async def close(self):
        """Close database connection pool"""
        if self.pool:
            await self.pool.close()
            self.pool = None
            self._connected = False
            print("✅ Auth Database pool closed")

    @asynccontextmanager
    async def connection(self):
        """Get a database connection from the pool"""
        if self.pool is None:
            raise RuntimeError(
                "Database not connected. Call await db.connect() first. "
                "Example: await db_auth.connect() in startup event"
            )
        try:
            async with self.pool.acquire() as conn:
                yield conn
        except Exception as e:
            print(f"❌ Database connection error: {e}")
            raise

    async def health_check(self):
        """Check if database is reachable"""
        try:
            async with self.connection() as conn:
                await conn.fetchval("SELECT 1")
            return True
        except:
            return False

    @property
    def is_connected(self):
        """Check if pool is connected"""
        return self._connected and self.pool is not None


# Create and export the instance
db_auth = Database_auth()

# Optional: Add async initialization helper
async def init_db():
    """Initialize database connection"""
    await db_auth.connect()
    return db_auth