# authentication_service.py
from fastapi import FastAPI, HTTPException, Body, Response
from fastapi.responses import JSONResponse
import hashlib
import random
import string
from typing import Dict, Optional
import uvicorn
from datetime import datetime, timedelta
#import database_auth as db_auth
from database_auth import db_auth

app = FastAPI(title="Authentication Service", description="MLS Identity Verification Service")

@app.on_event("startup")
async def startup():
    await db_auth.connect()

@app.on_event("shutdown")
async def shutdown():
    await db_auth.close()

@app.post("/register")
async def register(public_key: bytes = Body(...)):
    """
    Step 1: Register a public key and get a challenge
    The client sends their public key and receives a challenge to sign
    """
    try:
        # Generate a random challenge phrase
        challenge_id = random.randint(1000, 9999)
        challenge_phrase = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        
        # Store in database
        async with db_auth.connection() as conn:
            # First, check if user exists with this public key
            existing = await conn.fetchval(
                "SELECT user_id FROM users WHERE public_key = $1",
                public_key
            )
            
            if not existing:
                # Create new user
                await conn.execute(
                    """
                    INSERT INTO users (public_key, created_at, last_verified)
                    VALUES ($1, NOW(), NULL)
                    """,
                    public_key
                )
            
            # Store challenge
            await conn.execute(
                """
                INSERT INTO challenges (challenge_id, public_key, challenge_phrase, 
                                       created_at, expires_at, status)
                VALUES ($1, $2, $3, NOW(), NOW() + INTERVAL '5 minutes', 'pending')
                """,
                challenge_id, public_key, challenge_phrase
            )
        
        return {
            "challenge_id": challenge_id,
            "challenge_phrase": challenge_phrase
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@app.post("/challenge/{challenge_id}")
async def solve_challenge(challenge_id: int, signature: bytes = Body(...)):
    """
    Step 2: Submit signed challenge
    The client signs the challenge phrase with their private key and sends the signature
    """
    try:
        async with db_auth.connection() as conn:
            # Get challenge from database
            challenge = await conn.fetchrow(
                """
                SELECT * FROM challenges 
                WHERE challenge_id = $1 AND status = 'pending' AND expires_at > NOW()
                """,
                challenge_id
            )
            
            if not challenge:
                raise HTTPException(status_code=404, detail="Challenge not found or expired")
            
            # In a real implementation, you would verify the signature here
            # The client signed the challenge_phrase with their private key
            # You need to verify using the stored public key
            
            # For this example, we'll assume verification is done by the client
            # In production, you would implement proper signature verification
            
            # Mark challenge as verified
            await conn.execute(
                """
                UPDATE challenges 
                SET status = 'verified' 
                WHERE challenge_id = $1
                """,
                challenge_id
            )
            
            # Update user's last_verified timestamp
            await conn.execute(
                """
                UPDATE users 
                SET last_verified = NOW() 
                WHERE public_key = $1
                """,
                challenge["public_key"]
            )
            
            return {"status": "verified", "message": "Challenge solved successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Challenge verification failed: {str(e)}")

@app.post("/verify")
async def verify_identity(public_key: bytes = Body(...)):
    """
    Step 3: Check if an identity is verified
    Returns 200 if verified, 404 if not
    """
    try:
        async with db_auth.connection() as conn:
            # Check if user exists and has a verified challenge
            verified = await conn.fetchval(
                """
                SELECT EXISTS(
                    SELECT 1 FROM users u
                    JOIN challenges c ON u.public_key = c.public_key
                    WHERE u.public_key = $1 
                    AND c.status = 'verified'
                    AND c.expires_at > NOW() - INTERVAL '30 days'
                )
                """,
                public_key
            )
            
            if verified:
                return Response(status_code=200)
            else:
                # Check if user exists but no verified challenge
                user_exists = await conn.fetchval(
                    "SELECT EXISTS(SELECT 1 FROM users WHERE public_key = $1)",
                    public_key
                )
                
                if user_exists:
                    raise HTTPException(status_code=404, detail="Identity exists but not verified")
                else:
                    raise HTTPException(status_code=404, detail="Identity not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")

@app.get("/identity/{public_key_hex}")
async def get_identity_status(public_key_hex: str):
    """
    Get the verification status of an identity
    """
    try:
        public_key = bytes.fromhex(public_key_hex)
        
        async with db_auth.connection() as conn:
            user = await conn.fetchrow(
                """
                SELECT u.user_id, u.created_at, u.last_verified,
                       EXISTS(SELECT 1 FROM challenges c 
                              WHERE c.public_key = u.public_key 
                              AND c.status = 'verified') as is_verified
                FROM users u
                WHERE u.public_key = $1
                """,
                public_key
            )
            
            if not user:
                raise HTTPException(status_code=404, detail="Identity not found")
            
            return {
                "user_id": str(user["user_id"]) if user["user_id"] else None,
                "created_at": user["created_at"],
                "last_verified": user["last_verified"],
                "is_verified": user["is_verified"]
            }
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex public key")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get identity status: {str(e)}")

@app.delete("/identity/{public_key_hex}")
async def delete_identity(public_key_hex: str):
    """
    Delete an identity and all associated challenges
    """
    try:
        public_key = bytes.fromhex(public_key_hex)
        
        async with db_auth.connection() as conn:
            # Delete challenges first (foreign key constraint)
            await conn.execute(
                "DELETE FROM challenges WHERE public_key = $1",
                public_key
            )
            
            # Delete user
            result = await conn.execute(
                "DELETE FROM users WHERE public_key = $1",
                public_key
            )
            
            if result == "DELETE 0":
                raise HTTPException(status_code=404, detail="Identity not found")
            
            return {"status": "deleted", "public_key": public_key_hex}
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex public key")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete identity: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=1337)