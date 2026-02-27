# main.py (FastAPI)
from fastapi import FastAPI, Body, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
from uuid import UUID, uuid4
from datetime import datetime, timedelta
import jwt
from fastapi.responses import Response
from typing import Dict
from database import db
import hashlib  # for ref_hash computation

app = FastAPI()
# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT config (replace with your secret)
JWT_SECRET = "your-secret-key"  # Change to strong secret in .env
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

class UserCreate(BaseModel):
    username: str
    password: str

class UserDelete(BaseModel):
    user_id: UUID

@app.on_event("startup")
async def startup():
    await db.connect()

@app.on_event("shutdown")
async def shutdown():
    await db.close()

@app.post("/users")
async def register_user(user: UserCreate):
    password_hash = pwd_context.hash(user.password)
    print(f"Registering user: {user.username}, hashed password: {password_hash}")
    async with db.connection() as conn:
        user_id = await conn.fetchval(
            """
            INSERT INTO users (username, password_hash, created_at, last_active)
            VALUES ($1, $2, NOW(), NOW())
            RETURNING user_id
            """,
            user.username, password_hash
        )
        if not user_id:
            raise HTTPException(status_code=400, detail="Username already exists")
    return {"status": "registered", "user_id": str(user_id)}

@app.post("/login")
async def login_user(form_data: OAuth2PasswordRequestForm = Depends()):
    async with db.connection() as conn:
        row = await conn.fetchrow(
            """
            SELECT user_id, password_hash
            FROM users
            WHERE username = $1
            """,
            form_data.username
        )
        if not row or not pwd_context.verify(form_data.password, row["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid username or password")

        token = jwt.encode(
            {"user_id": str(row["user_id"]), "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)},
            JWT_SECRET,
            algorithm=JWT_ALGORITHM
        )

    return {"status": "logged in", "user_id": str(row["user_id"]), "access_token": token, "token_type": "bearer"}

@app.delete("/users/{user_id}")
async def delete_user(user_id: UUID, token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if str(payload["user_id"]) != str(user_id):
            raise HTTPException(status_code=401, detail="Unauthorized")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    async with db.connection() as conn:
        await conn.execute(
            """
            DELETE FROM users
            WHERE user_id = $1
            """,
            str(user_id)
        )
    return {"status": "deleted", "user_id": str(user_id)}

@app.post("/key_packages/{user_id}")
async def upload_keypackage(user_id: UUID, key_package: bytes = Body(...)):
    """
    Upload a new KeyPackage for a user.
    Computes ref_hash automatically.
    """
    # Compute KeyPackageRef (common MLS convention: SHA256 of the serialized KeyPackageTBS or full package)
    ref_hash = hashlib.sha256(key_package).digest()

    async with db.connection() as conn:
        try:
            kp_id = await conn.fetchval(
                """
                SELECT insert_key_package($1, $2, $3, NOW() + INTERVAL '30 days')
                """,
                str(user_id), key_package, ref_hash
            )
            return {"status": "uploaded", "key_package_id": str(kp_id), "ref_hash": ref_hash.hex()}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))


@app.get("/key_packages/{user_id}/latest")
async def get_latest_unused_keypackage(user_id: UUID):
    """
    Get the latest unused, non-expired KeyPackage for a user.
    Returns raw binary data.
    """
    async with db.connection() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM get_latest_unused_key_package($1)",
            str(user_id)
        )
        if not row:
            raise HTTPException(status_code=404, detail="No unused KeyPackage found")

        return Response(
            content=row["key_package"],
            media_type="application/octet-stream",
            headers={"X-Ref-Hash": row["ref_hash"].hex()}
        )


@app.post("/key_packages/mark_used")
async def mark_keypackage_used(ref_hash_hex: str = Body(...)):
    """
    Mark a KeyPackage as used (by its ref_hash in hex).
    """
    try:
        ref_hash = bytes.fromhex(ref_hash_hex)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex ref_hash")

    async with db.connection() as conn:
        updated = await conn.fetchval(
            "SELECT mark_key_package_used($1)",
            ref_hash
        )
        if not updated:
            raise HTTPException(status_code=404, detail="KeyPackage not found or already used")

        return {"status": "marked as used"}


@app.post("/cleanup")
async def cleanup_expired_packages():
    """
    Run cleanup of expired or used KeyPackages.
    Returns number of deleted rows.
    """
    async with db.connection() as conn:
        count = await conn.fetchval("SELECT cleanup_old_key_packages()")
        return {"cleaned": count}
    
@app.get("/test-db")
async def test_db():
    async with db.connection() as conn:
        version = await conn.fetchval("SELECT version()")
        return {"status": "connected", "postgres_version": version}