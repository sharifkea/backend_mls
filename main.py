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
from pydantic import BaseModel
from typing import Optional, List
import base64, secrets
import os
from dotenv import load_dotenv

load_dotenv()  # loads .env file


app = FastAPI()
# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT config 
JWT_SECRET = os.getenv("SECRET_KEY")  # strong secret key from .env
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

class GroupCreate(BaseModel):
    group_name: Optional[str] = None
    cipher_suite: int
    group_id: Optional[str] = None

class GroupResponse(BaseModel):
    group_id: str
    group_name: Optional[str]
    creator_user_id: str
    epoch: int
    created_at: datetime

class AddMemberRequest(BaseModel):
    user_id: str
    leaf_index: int

class MessageSend(BaseModel):
    group_id: str
    ciphertext: str  # base64 encoded
    nonce: str       # base64 encoded
    epoch: int
    content_type: int
    authenticated_data: Optional[str] = None
    encrypted_sender_data: Optional[str] = None
    wire_format: int

class MessageResponse(BaseModel):
    message_id: str
    group_id: str
    sender_user_id: str
    sender_leaf_index: int
    epoch: int
    ciphertext: str  # base64 encoded
    nonce: str       # base64 encoded
    created_at: datetime

class UserCreate(BaseModel):
    username: str
    password: str

class MarkUsedRequest(BaseModel):
    ref_hash: str
    
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
@app.get("/users")
async def get_users(
    username: Optional[str] = None,
    search: Optional[str] = None,
    token: str = Depends(oauth2_scheme)
):
    """
    Get users information.
    - If username is provided, exact match
    - If search is provided, partial match
    - If neither, returns all users
    """
    # Verify token
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        requester_id = payload["user_id"]
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    async with db.connection() as conn:
        if username:
            # Exact match by username
            rows = await conn.fetch(
                "SELECT user_id, username, created_at FROM users WHERE username = $1",
                username
            )
        elif search:
            # Partial match (case-insensitive)
            rows = await conn.fetch(
                "SELECT user_id, username, created_at FROM users WHERE username ILIKE $1",
                f"%{search}%"
            )
        else:
            # All users (limit to 100 for performance)
            rows = await conn.fetch(
                "SELECT user_id, username, created_at FROM users ORDER BY created_at DESC LIMIT 100"
            )
    
    return {
        "users": [
            {
                "user_id": str(row["user_id"]),
                "username": row["username"],
                "created_at": row["created_at"].isoformat()
            }
            for row in rows
        ]
    }

@app.get("/users/{user_id}")
async def get_user_by_id(
    user_id: UUID,
    token: str = Depends(oauth2_scheme)
):
    """
    Get a specific user by ID.
    """
    # Verify token
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        requester_id = payload["user_id"]
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    async with db.connection() as conn:
        row = await conn.fetchrow(
            """
            SELECT 
                user_id, 
                username, 
                created_at,
                last_active,
                (SELECT COUNT(*) FROM group_members WHERE user_id = $1 AND is_active = TRUE) as group_count
            FROM users 
            WHERE user_id = $1
            """,
            str(user_id)
        )
        
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {
            "user_id": str(row["user_id"]),
            "username": row["username"],
            "created_at": row["created_at"].isoformat(),
            "last_active": row["last_active"].isoformat(),
            "group_count": row["group_count"]
        }
    
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

@app.post("/key_packages/mark-used")
async def mark_keypackage_used(request: MarkUsedRequest):
    """
    Mark a KeyPackage as used (by its ref_hash in hex).
    """
    ref_hash_hex = request.ref_hash
    print(f"Marking KeyPackage as used with ref_hash: {ref_hash_hex}")
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

@app.post("/cleanup")
async def cleanup_expired_packages():
    """
    Run cleanup of expired or used KeyPackages.
    Returns number of deleted rows.
    """
    async with db.connection() as conn:
        count = await conn.fetchval("SELECT cleanup_old_key_packages()")
        return {"cleaned": count}
    
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

@app.post("/groups")
async def create_group(group: GroupCreate, token: str = Depends(oauth2_scheme)):
    """Create a new MLS group - accepts client-generated group ID"""
    user_id = verify_token(token)
    
    # Use client-provided group_id if available
    if group.group_id:
        try:
            group_id_bytes = base64.b64decode(group.group_id)
            if len(group_id_bytes) != 16:
                raise HTTPException(status_code=400, detail="Group ID must be 16 bytes")
            print(f"Using client-provided group ID: {group.group_id}")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid group_id format: {e}")
    else:
        # Fall back to server-generated ID
        group_id_bytes = secrets.token_bytes(16)
        print("Generated new group ID")
    
    async with db.connection() as conn:
        try:
            success = await conn.fetchval(
                "SELECT create_group($1, $2, $3, $4)",
                group_id_bytes, group.group_name, user_id, group.cipher_suite
            )
            return {
                "status": "created",
                "group_id": base64.b64encode(group_id_bytes).decode('ascii')
            }
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

@app.post("/groups/{group_id}/members")
async def add_group_member(group_id: str, request: AddMemberRequest, token: str = Depends(oauth2_scheme)):
    """Add a member to a group"""
    user_id = verify_token(token)
    group_id_bytes = base64.b64decode(group_id)
    
    async with db.connection() as conn:
        await conn.fetchval(
            "SELECT add_group_member($1, $2, $3, $4)",
            group_id_bytes, request.user_id, request.leaf_index, user_id
        )
    
    return {"status": "member_added"}

@app.get("/groups/{group_id}")
async def get_group(group_id: str, token: str = Depends(oauth2_scheme)):
    """Get group details"""
    verify_token(token)  # Just verify, don't need user_id
    group_id_bytes = base64.b64decode(group_id)
    
    async with db.connection() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM get_group_details($1)",
            group_id_bytes
        )
    
    if not row:
        raise HTTPException(status_code=404, detail="Group not found")
    
    return {
        "group_id": group_id,
        "group_name": row["group_name"],
        "creator_user_id": str(row["creator_user_id"]),
        "creator_username": row["creator_username"],
        "cipher_suite": row["cipher_suite"],
        "epoch": row["last_epoch"],
        "created_at": row["created_at"],
        "member_count": row["member_count"]
    }

@app.get("/users/me/groups")
async def get_my_groups(token: str = Depends(oauth2_scheme)):
    """Get all groups for current user with membership details"""
    user_id = verify_token(token)
    
    async with db.connection() as conn:
        rows = await conn.fetch(
            """
            SELECT 
                g.group_id,
                g.group_name,
                g.last_epoch,
                g.cipher_suite,
                COUNT(DISTINCT gm_all.user_id) as member_count,
                MAX(m.created_at) as last_message_at,
                gm.leaf_index as my_leaf_index,
                gm.joined_at as my_joined_at
            FROM groups g
            JOIN group_members gm ON g.group_id = gm.group_id AND gm.user_id = $1
            LEFT JOIN group_members gm_all ON g.group_id = gm_all.group_id AND gm_all.is_active = TRUE
            LEFT JOIN messages m ON g.group_id = m.group_id
            WHERE gm.is_active = TRUE
            GROUP BY g.group_id, g.group_name, g.last_epoch, g.cipher_suite, gm.leaf_index, gm.joined_at
            ORDER BY g.last_updated DESC
            """,
            user_id
        )
    
    return {
        "groups": [
            {
                "group_id": base64.b64encode(row["group_id"]).decode('ascii'),
                "group_name": row["group_name"],
                "cipher_suite": row["cipher_suite"],
                "epoch": row["last_epoch"],
                "member_count": row["member_count"],
                "last_message_at": row["last_message_at"].isoformat() if row["last_message_at"] else None,
                "my_leaf_index": row["my_leaf_index"],  # 🔑 Alice's leaf index in this group
                "my_joined_at": row["my_joined_at"].isoformat()
            }
            for row in rows
        ]
    }

@app.post("/messages")
async def send_message(message: MessageSend, token: str = Depends(oauth2_scheme)):
    """Store an encrypted message"""
    user_id = verify_token(token)
    
    # Decode data
    group_id_bytes = base64.b64decode(message.group_id)
    ciphertext_bytes = base64.b64decode(message.ciphertext)
    nonce_bytes = base64.b64decode(message.nonce)
    auth_data = base64.b64decode(message.authenticated_data) if message.authenticated_data else b''
    enc_sender = base64.b64decode(message.encrypted_sender_data) if message.encrypted_sender_data else b''
    
    async with db.connection() as conn:
        message_id = await conn.fetchval(
            """
            SELECT store_message($1, $2, $3, $4, $5, $6, $7, $8, $9)
            """,
            group_id_bytes, user_id, message.epoch, ciphertext_bytes, nonce_bytes,
            message.content_type, auth_data, enc_sender, message.wire_format
        )
    
    return {
        "status": "stored",
        "message_id": str(message_id)
    }

@app.get("/groups/{group_id}/messages")
async def get_messages(
    group_id: str, 
    since_epoch: Optional[int] = None,
    limit: int = 100,
    token: str = Depends(oauth2_scheme)
):
    """Get messages from a group"""
    user_id = verify_token(token)
    group_id_bytes = base64.b64decode(group_id)
    
    async with db.connection() as conn:
        rows = await conn.fetch(
            "SELECT * FROM get_group_messages($1, $2, $3, $4)",
            group_id_bytes, user_id, since_epoch, limit
        )
    
    return {
        "messages": [
            {
                "message_id": str(row["message_id"]),
                "sender_user_id": str(row["sender_user_id"]),
                "sender_username": row["sender_username"],
                "sender_leaf_index": row["sender_leaf_index"],
                "epoch": row["epoch"],
                "ciphertext": base64.b64encode(row["ciphertext"]).decode('ascii'),
                "nonce": base64.b64encode(row["nonce"]).decode('ascii'),
                "content_type": row["content_type"],
                "created_at": row["created_at"].isoformat()
            }
            for row in rows
        ]
    }

@app.post("/groups/{group_id}/epoch")
async def update_epoch(
    group_id: str,
    new_epoch: int,
    epoch_secret: Optional[str] = None,
    token: str = Depends(oauth2_scheme)
):
    """Update group to new epoch"""
    user_id = verify_token(token)
    group_id_bytes = base64.b64decode(group_id)
    secret_bytes = base64.b64decode(epoch_secret) if epoch_secret else None
    
    async with db.connection() as conn:
        await conn.fetchval(
            "SELECT update_group_epoch($1, $2, $3, $4)",
            group_id_bytes, new_epoch, user_id, secret_bytes
        )
    
    return {"status": "updated", "new_epoch": new_epoch}

# Helper function
def verify_token(token: str) -> str:
    """Verify JWT token and return user_id"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload["user_id"]
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
@app.get("/test-db")
async def test_db():
    async with db.connection() as conn:
        version = await conn.fetchval("SELECT version()")
        return {"status": "connected", "postgres_version": version}

@app.get("/groups/{group_id}/messages")
async def get_group_messages_debug(
    group_id: str,
    since_epoch: Optional[int] = None,
    limit: int = 100,
    token: str = Depends(oauth2_scheme)
):
    """Debug version to see what's happening"""
    print(f"\n=== DEBUG: get_group_messages called ===")
    print(f"group_id: {group_id}")
    print(f"since_epoch: {since_epoch}")
    print(f"limit: {limit}")
    
    # Verify token
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload["user_id"]
        print(f"user_id from token: {user_id}")
    except Exception as e:
        print(f"Token error: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Decode group_id
    try:
        group_id_bytes = base64.b64decode(group_id)
        print(f"Decoded group_id bytes: {group_id_bytes.hex()}")
        print(f"Decoded group_id length: {len(group_id_bytes)} bytes")
    except Exception as e:
        print(f"Base64 decode error: {e}")
        raise HTTPException(status_code=400, detail="Invalid group_id format")
    
    # Check database connection
    try:
        async with db.connection() as conn:
            # Test 1: Check if user exists
            user_exists = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM users WHERE user_id = $1)",
                user_id
            )
            print(f"User exists in DB: {user_exists}")
            
            # Test 2: Check if group exists
            group_exists = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM groups WHERE group_id = $1)",
                group_id_bytes
            )
            print(f"Group exists in DB: {group_exists}")
            
            # Test 3: Check if user is member
            is_member = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2)",
                group_id_bytes, user_id
            )
            print(f"User is member: {is_member}")
            
            # Test 4: Count messages
            msg_count = await conn.fetchval(
                "SELECT COUNT(*) FROM messages WHERE group_id = $1",
                group_id_bytes
            )
            print(f"Messages in group: {msg_count}")
            
            # Now try the actual function
            try:
                rows = await conn.fetch(
                    "SELECT * FROM get_group_messages($1, $2, $3, $4)",
                    group_id_bytes, user_id, since_epoch, limit
                )
                print(f"Query returned {len(rows)} rows")
                
                # Format response
                messages = []
                for row in rows:
                    messages.append({
                        "message_id": str(row["message_id"]),
                        "group_id": group_id,
                        "sender_user_id": str(row["sender_user_id"]),
                        "sender_username": row["sender_username"],
                        "sender_leaf_index": row["sender_leaf_index"],
                        "epoch": row["epoch"],
                        "ciphertext": base64.b64encode(row["ciphertext"]).decode('ascii'),
                        "nonce": base64.b64encode(row["nonce"]).decode('ascii'),
                        "content_type": row["content_type"],
                        "created_at": row["created_at"].isoformat()
                    })
                
                return {"messages": messages, "count": len(messages)}
                
            except Exception as e:
                print(f"Database function error: {e}")
                import traceback
                traceback.print_exc()
                raise HTTPException(status_code=500, detail=str(e))
                
    except Exception as e:
        print(f"Database connection error: {e}")
        raise HTTPException(status_code=500, detail=str(e))