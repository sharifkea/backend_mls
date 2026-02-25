# main.py (FastAPI)
from fastapi import FastAPI, Body, HTTPException, status
from fastapi.responses import Response
from typing import Dict
from uuid import UUID
from database import db
import hashlib  # for ref_hash computation

app = FastAPI()

@app.on_event("startup")
async def startup():
    await db.connect()

@app.on_event("shutdown")
async def shutdown():
    await db.close()

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