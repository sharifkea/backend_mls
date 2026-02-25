import asyncio
import asyncpg

async def connect_mls_db():
    """Async connection to MLS database"""
    try:
        # Connection parameters
        conn = await asyncpg.connect(
            host='localhost',
            port=5432,
            database='mls_db',
            user='postgres',
            password='my_password'
        )
        
        print("✅ Connected to mls_db asynchronously!")
        
        # Get PostgreSQL version
        version = await conn.fetchval('SELECT version()')
        print(f"📊 Version: {version[:50]}...")  # First 50 chars
        
        # Get list of tables
        tables = await conn.fetch("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
        """)
        
        if tables:
            print("\n📋 Tables found:")
            for table in tables:
                print(f"  - {table['table_name']}")
        else:
            print("\n📋 No tables found in public schema")
        
        await conn.close()
        print("🔒 Connection closed.")
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")

# Run async function
if __name__ == "__main__":
    asyncio.run(connect_mls_db())