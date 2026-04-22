# main.py (FastAPI)
import binascii
from fastapi import WebSocket, WebSocketDisconnect
from typing import Dict
import json
import asyncio

from fastapi import FastAPI, Body, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
from uuid import UUID, uuid4
from datetime import datetime, timedelta
import jwt
from fastapi.responses import Response
from typing import Dict
import pydantic
from database import db
import hashlib  # for ref_hash computation
from pydantic import BaseModel
from typing import Optional, List
import base64, secrets
import os
from dotenv import load_dotenv
from typing import Optional
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware



load_dotenv()  # loads .env file

app = FastAPI()
# Add this after creating the FastAPI app
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5000", "http://127.0.0.1:5000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT config 
JWT_SECRET = os.getenv("SECRET_KEY")  # strong secret key from .env
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Connection manager for WebSocket
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_sessions: Dict[str, str] = {}
    
    async def connect(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        self.active_connections[user_id] = websocket
        print(f"✅ WebSocket connected: {user_id}")
    
    def disconnect(self, user_id: str):
        if user_id in self.active_connections:
            del self.active_connections[user_id]
            print(f"❌ WebSocket disconnected: {user_id}")
    
    async def send_to_user(self, user_id: str, message: dict):
        print(f"📤 Attempting to send to user {user_id}")
        print(f"   Active connections: {list(self.active_connections.keys())}")
        
        if user_id in self.active_connections:
            try:
                await self.active_connections[user_id].send_json(message)
                print(f"✅ Successfully sent to {user_id}")
                return True
            except Exception as e:
                print(f"❌ Failed to send to {user_id}: {e}")
                self.disconnect(user_id)
        else:
            print(f"⚠️ User {user_id} not in active connections")
        return False
    
    async def broadcast_to_group(self, group_id_b64: str, message: dict, exclude_user: str = None):
        """Broadcast message to all members of a group"""
        try:
            # Handle special "all" group (broadcast to all connected users)
            if group_id_b64 == "all":
                for user_id, connection in self.active_connections.items():
                    if user_id != exclude_user:
                        try:
                            await connection.send_json(message)
                        except:
                            pass
                return
            
            # Normal group broadcast
            group_id_bytes = base64.b64decode(group_id_b64)
            async with db.connection() as conn:
                rows = await conn.fetch(
                    "SELECT user_id FROM group_members WHERE group_id = $1 AND is_active = TRUE",
                    group_id_bytes
                )
                print(f"📡 Broadcasting to group, found {len(rows)} members")
                for row in rows:
                    user_id = str(row["user_id"])
                    if user_id != exclude_user and user_id in self.active_connections:
                        try:
                            await self.active_connections[user_id].send_json(message)
                            print(f"   ✅ Sent to {user_id[:8]}...")
                        except Exception as e:
                            print(f"   ❌ Failed to send to {user_id[:8]}...: {e}")
        except Exception as e:
            print(f"❌ Broadcast error: {e}")
            import traceback
            traceback.print_exc()

class GroupUpdateNotification(BaseModel):
    group_id: str
    update_data: dict
    exclude_user: str

class NewUserNotification(BaseModel):
    creator_id: str
    new_user_id: str
    new_username: str
    group_id: str
    group_name: str
    
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

class EpochUpdate(BaseModel):
    new_epoch: int

class JoinRequestNotification(BaseModel):
    creator_id: str
    requester_id: str
    requester_username: str
    group_id: str
    group_name: str

class MemberUpdateNotification(BaseModel):
    user_id: str
    group_id: str
    update_data: dict

manager = ConnectionManager()


@app.post("/api/notify-join-request")
async def notify_join_request(notification: JoinRequestNotification):
    """Notify group creator about join request"""
    
    print(f"📢 Join request from {notification.requester_username} for group {notification.group_name}")
    print(f"   Creator ID: {notification.creator_id}")
    print(f"   Active connections: {list(manager.active_connections.keys())}")
    
    if notification.creator_id in manager.active_connections:
        print(f"   ✅ Creator is online, sending notification...")
        
        # Create the message
        ws_message = {
            'type': 'join_request',
            'requester_id': notification.requester_id,
            'requester_username': notification.requester_username,
            'group_id': notification.group_id,
            'group_name': notification.group_name
        }
        
        print(f"   Message: {ws_message}")
        
        # Send directly to verify
        try:
            await manager.active_connections[notification.creator_id].send_json(ws_message)
            print(f"✅ Notified creator {notification.creator_id}")
            return {"status": "notified"}
        except Exception as e:
            print(f"❌ Direct send failed: {e}")
            return {"status": "send_failed"}
    else:
        print(f"⚠️ Creator {notification.creator_id} not connected")
        print(f"   Connected users: {list(manager.active_connections.keys())}")
        return {"status": "creator_offline"}

# WebSocket endpoint  
@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str):
    username = websocket.query_params.get("username", "Unknown")
    
    print(f"🔌 WebSocket connection attempt from {username} ({user_id})")
    
    await manager.connect(websocket, user_id)
    print(f"✅ WebSocket connected for {username}")
    
    try:
        while True:
            # Add timeout to detect hangs
            data = await asyncio.wait_for(websocket.receive_text(), timeout=60.0)
            message = json.loads(data)
            msg_type = message.get("type")
            
            if msg_type == "ping":
                await websocket.send_json({"type": "pong"})
                print(f"💓 Ping from {user_id}")
            
            elif msg_type == "new_message_notification":
                group_id_b64 = message.get("group_id_b64")
                sender_username = message.get("sender_username")
                
                # Just notify others to refresh messages
                await manager.broadcast_to_group(
                    group_id_b64,
                    {
                        "type": "refresh_messages",
                        "group_id_b64": group_id_b64,
                        "sender_username": sender_username
                    },
                    exclude_user=user_id
                )
            elif msg_type == "send_message":
                # Extract message data (format from frontend)
                group_id_b64 = message.get("group_id_b64")
                ciphertext = message.get("ciphertext")
                nonce = message.get("nonce")
                epoch = message.get("epoch")
                sender_username = message.get("sender_username")
                sender_leaf_index = message.get("sender_leaf_index")
                message_generation = message.get("message_generation", 0)
                
                print(f"📨 Received send_message from {sender_username} to group {group_id_b64[:8]}...")
                
                # Store in database (for offline users)
                try:
                    group_id_bytes = base64.b64decode(group_id_b64)
                    ciphertext_bytes = base64.b64decode(ciphertext)
                    nonce_bytes = base64.b64decode(nonce)
                    
                    async with db.connection() as conn:
                        await conn.fetchval(
                            """
                            SELECT store_message($1, $2, $3, $4, $5, $6, $7, $8, $9)
                            """,
                            group_id_bytes, user_id, epoch, ciphertext_bytes, nonce_bytes,
                            1, b'', b'', 2
                        )
                    print(f"💾 Message stored in database")
                except Exception as e:
                    print(f"❌ Failed to store message: {e}")
                
                # Broadcast to all group members in real-time
                await manager.broadcast_to_group(
                    group_id_b64,
                    {
                        "type": "new_message",
                        "group_id_b64": group_id_b64,
                        "sender_user_id": user_id,
                        "sender_username": sender_username,
                        "ciphertext": ciphertext,
                        "nonce": nonce,
                        "epoch": epoch,
                        "sender_leaf_index": sender_leaf_index,
                        "message_generation": message_generation
                    },
                    exclude_user=user_id
                )
                print(f"📡 Broadcasted message to group {group_id_b64[:8]}...")
                
                # Send confirmation back to sender
                await websocket.send_json({
                    "type": "message_sent",
                    "success": True,
                    "message_id": "stored"
                })
            
            elif msg_type == "join_group":
                group_id = message.get("group_id")
                print(f"User {user_id} joined group room: {group_id}")
                await websocket.send_json({"type": "joined", "group_id": group_id})
            
            elif msg_type == "get_online_users":
                online_users = list(manager.active_connections.keys())
                await websocket.send_json({
                    "type": "online_users",
                    "users": online_users
                })
    
    except WebSocketDisconnect:
        manager.disconnect(user_id)
        await manager.broadcast_to_group("all", {
            "type": "user_offline",
            "user_id": user_id,
            "username": username
        })

@app.post("/api/notify-new-user")
async def notify_new_user(notification: NewUserNotification):
    """Receive notification from Flask about new user who should join a group"""
    
    # Send WebSocket message to the creator if they're connected
    if notification.creator_id in manager.active_connections:
        await manager.send_to_user(notification.creator_id, {
            'type': 'new_user_ready_to_join',
            'new_user_id': notification.new_user_id,
            'new_username': notification.new_username,
            'group_id': notification.group_id,
            'group_name': notification.group_name
        })
        print(f"📢 Notified creator {notification.creator_id} about new user {notification.new_username}")
    
    return {"status": "notified"}

@app.post("/api/notify-group-update")
async def notify_member_update(notification: MemberUpdateNotification):
    """Notify a specific member about group update"""
    
    print(f"📢 Attempting to notify member: {notification.user_id}")
    print(f"   Active connections: {list(manager.active_connections.keys())}")
    
    if notification.user_id in manager.active_connections:
        await manager.send_to_user(notification.user_id, {
            'type': 'group_update',
            'group_id': notification.group_id,
            'update_data': notification.update_data
        })
        print(f"✅ Notified member {notification.user_id}")
        return {"status": "notified"}
    else:
        print(f"⚠️ Member {notification.user_id} not connected (offline)")
        return {"status": "offline"}
    
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
    """Create a new MLS group"""
    user_id = verify_token(token)
    
    # Check if client provided a group_id
    if group.group_id:
        try:
            # Try to decode as base64 first
            group_id_bytes = base64.b64decode(group.group_id)
            print(f"Decoded base64 group_id: {len(group_id_bytes)} bytes")
            
            # Verify it's 16 bytes
            if len(group_id_bytes) != 16:
                raise HTTPException(status_code=400, detail="Group ID must be 16 bytes")
                
        except Exception as e:
            # If base64 fails, try hex
            try:
                if len(group.group_id) == 32:  # 16 bytes in hex = 32 chars
                    group_id_bytes = bytes.fromhex(group.group_id)
                    print(f"Decoded hex group_id: {len(group_id_bytes)} bytes")
                else:
                    raise HTTPException(status_code=400, detail="Invalid group_id format")
            except:
                raise HTTPException(status_code=400, detail="Invalid group_id format")
    else:
        # Generate new group_id
        group_id_bytes = secrets.token_bytes(16)
    
    # Rest of your code...
    async with db.connection() as conn:
        success = await conn.fetchval(
            "SELECT create_group($1, $2, $3, $4)",
            group_id_bytes, group.group_name, user_id, group.cipher_suite
        )
    
    return {
        "status": "created",
        "group_id": base64.b64encode(group_id_bytes).decode('ascii')
    }

@app.post("/groups/{group_id}/members")
async def add_group_member(
    group_id: str,  # This can be hex or base64
    request: AddMemberRequest,
    token: str = Depends(oauth2_scheme)
):
    """Add a member to a group"""
    user_id = verify_token(token)
    
    # Try to decode as hex first, then base64
    try:
        # Try hex first
        if len(group_id) == 32:  # 16 bytes = 32 hex chars
            group_id_bytes = bytes.fromhex(group_id)
        else:
            # Try base64
            group_id_bytes = base64.b64decode(group_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid group_id format")
    
    async with db.connection() as conn:
        # Your existing code...
        result = await conn.fetchval(
            "SELECT add_group_member($1, $2, $3, $4)",
            group_id_bytes, request.user_id, request.leaf_index, user_id
        )
        
        return {"status": "member_added"}
    
@app.get("/groups/{group_id}")
async def get_group_details_endpoint(
    group_id: str,
    token: str = Depends(oauth2_scheme)
):
    """Get detailed information about a group"""
    user_id = verify_token(token)
    
    try:
        # Try hex first (32 chars = 16 bytes)
        if len(group_id) == 32:
            group_id_bytes = bytes.fromhex(group_id)
            print(f"Decoded as hex: {group_id}")
        else:
            # Try base64
            group_id_bytes = base64.b64decode(group_id)
            print(f"Decoded as base64: {group_id}")
    except Exception:
        raise HTTPException(400, "Invalid group_id format")
    
    async with db.connection() as conn:
        # Call your SQL function
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
            "last_epoch": row["last_epoch"],
            "created_at": row["created_at"].isoformat(),
            "member_count": row["member_count"]
        }


@app.get("/groups/{group_id}/members")
async def get_group_members_endpoint(
    group_id: str,
    token: str = Depends(oauth2_scheme)
):
    """Get all members of a group"""
    user_id = verify_token(token)
    
    try:
        # Try hex first (32 chars = 16 bytes)
        if len(group_id) == 32:
            group_id_bytes = bytes.fromhex(group_id)
            print(f"Decoded as hex: {group_id}")
        else:
            # Try base64
            group_id_bytes = base64.b64decode(group_id)
            print(f"Decoded as base64: {group_id}")
    except Exception:
        raise HTTPException(400, "Invalid group_id format")
    print(f"User ID from token: {user_id}")
    print(f"Fetching members for group_id: {group_id} (bytes: {group_id_bytes.hex()})")
    async with db.connection() as conn:
        # Verify user is a member
        if not ( await conn.fetchval(
            "SELECT EXISTS(SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2)",
            group_id_bytes, user_id
        )):
            raise HTTPException(status_code=403, detail="Not a group member")
        
        # Get all members using SQL function or direct query
        rows = await conn.fetch(
            """
            SELECT 
                gm.user_id,
                u.username,
                gm.leaf_index,
                gm.joined_at,
                gm.is_active
            FROM group_members gm
            JOIN users u ON gm.user_id = u.user_id
            WHERE gm.group_id = $1 AND gm.is_active = TRUE
            ORDER BY gm.leaf_index
            """,
            group_id_bytes
        )
        
        return {
            "group_id": group_id,
            "members": [
                {
                    "user_id": str(row["user_id"]),
                    "username": row["username"],
                    "leaf_index": row["leaf_index"],
                    "joined_at": row["joined_at"].isoformat() if row["joined_at"] else None,
                    "is_active": row["is_active"]
                }
                for row in rows
            ]
        }

@app.post("/groups/{group_id}/epoch")
async def update_epoch(
    group_id: str,
    payload: EpochUpdate,  # Now only has new_epoch
    token: str = Depends(oauth2_scheme)
):
    """Update group to new epoch - NO secret storage!"""
    user_id = verify_token(token)
    
    # Try to decode as hex first, then base64
    try:
        if len(group_id) == 32:
            group_id_bytes = bytes.fromhex(group_id)
            print(f"Decoded as hex: {group_id}")
        else:
            group_id_bytes = base64.b64decode(group_id)
            print(f"Decoded as base64: {group_id}")
    except Exception:
        raise HTTPException(400, "Invalid group_id format")
    
    async with db.connection() as conn:
        await conn.fetchval(
            "SELECT update_group_epoch($1, $2, $3)",  # Only 3 parameters now
            group_id_bytes, payload.new_epoch, user_id
        )
    return {"status": "updated", "new_epoch": payload.new_epoch}


# Helper function
def verify_token(token: str) -> str:
    """Verify JWT token and return user_id"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload["user_id"]
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.get("/groups/{group_id}/messages")
async def get_group_messages(
    group_id: str,
    since_epoch: Optional[int] = None,  # ← Already there
    since_message_id: Optional[str] = None,
    limit: int = 100,
    token: str = Depends(oauth2_scheme)
):
    """Get messages - optionally since a specific message ID"""
    print(f"\n=== get_group_messages called ===")
    print(f"group_id: {group_id}")
    print(f"since_epoch: {since_epoch}")
    print(f"since_message_id: {since_message_id}")
    
    user_id = verify_token(token)
    
    # Decode group_id
    try:
        group_id_bytes = bytes.fromhex(group_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid group_id format")
    
    async with db.connection() as conn:
        # Verify user is a member
        is_member = await conn.fetchval(
            "SELECT EXISTS(SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2 AND is_active = TRUE)",
            group_id_bytes, user_id
        )
        
        if not is_member:
            raise HTTPException(status_code=403, detail="Not a group member")
        
        # Build query based on since_message_id
        if since_message_id:
            # Get messages after the specified message ID
            rows = await conn.fetch(
                """
                SELECT 
                    m.message_id,
                    encode(m.group_id, 'base64') as group_id_b64,
                    m.sender_user_id,
                    u.username as sender_username,
                    m.sender_leaf_index,
                    m.epoch,
                    encode(m.ciphertext, 'base64') as ciphertext_b64,
                    encode(m.nonce, 'base64') as nonce_b64,
                    m.content_type,
                    m.created_at
                FROM messages m
                JOIN users u ON m.sender_user_id = u.user_id
                WHERE m.group_id = $1 
                    AND m.created_at > (SELECT created_at FROM messages WHERE message_id = $2::UUID)
                    AND m.epoch = $3
                    AND m.sender_user_id != $4
                ORDER BY m.created_at ASC
                LIMIT $5
                """,
                group_id_bytes, since_message_id, since_epoch, user_id, limit
            )
        else:
            # First load - get recent messages (excluding user's own messages)
            rows = await conn.fetch(
                """
                SELECT 
                    m.message_id,
                    encode(m.group_id, 'base64') as group_id_b64,
                    m.sender_user_id,
                    u.username as sender_username,
                    m.sender_leaf_index,
                    m.epoch,
                    encode(m.ciphertext, 'base64') as ciphertext_b64,
                    encode(m.nonce, 'base64') as nonce_b64,
                    m.content_type,
                    m.created_at
                FROM messages m
                JOIN users u ON m.sender_user_id = u.user_id
                WHERE m.group_id = $1
                    AND m.epoch = $2 
                    AND m.sender_user_id != $3
                ORDER BY m.created_at ASC
                LIMIT $4
                """,
                group_id_bytes, since_epoch, user_id, limit
            )
        
        messages = []
        for row in rows:
            messages.append({
                "message_id": str(row["message_id"]),
                "group_id": row["group_id_b64"],
                "sender_user_id": str(row["sender_user_id"]),
                "sender_username": row["sender_username"],
                "sender_leaf_index": row["sender_leaf_index"],
                "epoch": row["epoch"],
                "ciphertext": row["ciphertext_b64"],
                "nonce": row["nonce_b64"],
                "content_type": row["content_type"],
                "created_at": row["created_at"].isoformat()
            })
        
        return {"messages": messages, "count": len(messages)}
    
@app.post("/groups/{group_id}/welcome")
async def store_welcome(
    group_id: str,                      # this is base64 string from frontend
    payload: dict,
    token: str = Depends(oauth2_scheme)
):
    user_id = verify_token(token)       # your function that returns UUID

    # 1. Decode group_id (base64 → raw bytes)
    # Try to decode as hex first, then base64
    try:
        # Try hex first (32 chars = 16 bytes)
        if len(group_id) == 32:
            group_id_bytes = bytes.fromhex(group_id)
            print(f"Decoded as hex: {group_id}")
        else:
            # Try base64
            group_id_bytes = base64.b64decode(group_id)
            print(f"Decoded as base64: {group_id}")
    except Exception:
        raise HTTPException(400, "Invalid group_id format")

    # 2. Decode welcome (base64 → bytes)
    try:
        welcome_bytes = base64.b64decode(payload["welcome_b64"])
    except Exception:
        raise HTTPException(400, "Invalid welcome_b64 (must be valid base64)")

    # 3. Get target user
    try:
        to_user_id = UUID(payload["to_user_id"])
    except Exception:
        raise HTTPException(400, "Invalid to_user_id (must be valid UUID)")
    
    print(f"Received group_id (b64): {group_id}")
    print(f"Decoded group_id_bytes len: {len(group_id_bytes)}")
    print(f"Received welcome_b64 len: {len(payload['welcome_b64'])}")
    print(f"Decoded welcome_bytes len: {len(welcome_bytes)}")
    print(f"Target user: {to_user_id}")

    async with db.connection() as conn:
        # Optional: verify caller is member (good security)
        is_member = await conn.fetchval(
            "SELECT EXISTS(SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2)",
            group_id_bytes, user_id
        )
        if not is_member:
            raise HTTPException(403, "Not a member of this group")

        # Insert / update
        result = await conn.execute(
            """
            INSERT INTO pending_welcomes (group_id, to_user_id, welcome)
            VALUES ($1, $2, $3)
            ON CONFLICT (group_id, to_user_id) 
            DO UPDATE SET
                welcome = EXCLUDED.welcome,
                created_at = NOW(),
                delivered = FALSE
            """,
            group_id_bytes,         # BYTEA
            to_user_id,             # UUID
            welcome_bytes           # BYTEA
        )

        print(f"Executed query - affected rows: {result}")

        if result == 0:
            raise HTTPException(500, "No rows affected - possible constraint violation")

    return {"status": "stored"}

@app.get("/pending-welcomes")
async def get_pending_welcomes(token: str = Depends(oauth2_scheme)):
    user_id = verify_token(token)
    print(f"Token: {token}")
    print(f"Fetching pending welcomes for user_id: {user_id}")
    async with db.connection() as conn:
        rows = await conn.fetch(
            """
            SELECT 
                encode(group_id, 'base64') AS group_id_b64,
                welcome, id
            FROM pending_welcomes
            WHERE to_user_id = $1 AND delivered = FALSE
            ORDER BY created_at DESC
            """,
            user_id
        )
    
    return {
        "welcomes": [
            {
                "group_id": row["group_id_b64"],
                "welcome_b64": base64.b64encode(row["welcome"]).decode('ascii'),
                "id": str(row["id"])
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

@app.get("/api/groups/search")
async def search_groups(
    group_name: str,
    token: str = Depends(oauth2_scheme)
):
    """Search for a group by name"""
    user_id = verify_token(token)
    
    async with db.connection() as conn:
        rows = await conn.fetch(
            """
            SELECT 
                g.group_id,
                g.group_name,
                g.creator_user_id,
                u.username as creator_username,
                g.last_epoch,
                COUNT(gm.user_id) as member_count
            FROM groups g
            JOIN users u ON g.creator_user_id = u.user_id
            LEFT JOIN group_members gm ON g.group_id = gm.group_id AND gm.is_active = TRUE
            WHERE g.group_name ILIKE $1 AND g.is_active = TRUE
            GROUP BY g.group_id, g.group_name, g.creator_user_id, u.username, g.last_epoch
            """,
            f"%{group_name}%"
        )
        
        return {
            "groups": [
                {
                    "group_id": base64.b64encode(row["group_id"]).decode('ascii'),
                    "group_name": row["group_name"],
                    "creator_user_id": str(row["creator_user_id"]),
                    "creator_username": row["creator_username"],
                    "last_epoch": row["last_epoch"],
                    "member_count": row["member_count"]
                }
                for row in rows
            ]
        }

@app.get("/test-db")
async def test_db():
    async with db.connection() as conn:
        version = await conn.fetchval("SELECT version()")
        return {"status": "connected", "postgres_version": version}

    
@app.post("/welcome/{welcome_id}/delivered")
async def mark_welcome_delivered(welcome_id: UUID, token: str = Depends(oauth2_scheme)):
    """Mark a welcome message as delivered"""
    user_id = verify_token(token)
    
    async with db.connection() as conn:
        # Verify the welcome belongs to this user
        result = await conn.execute(
            """
            UPDATE pending_welcomes 
            SET delivered = TRUE 
            WHERE id = $1 AND to_user_id = $2 AND delivered = FALSE
            """,
            str(welcome_id), user_id
        )
        
        if result == "UPDATE 0":
            raise HTTPException(status_code=404, detail="Welcome not found or already delivered")
        
        return {"status": "delivered"}
    
    async with db.connection() as conn:
        # Verify user is a member
        is_member = await conn.fetchval(
            "SELECT EXISTS(SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2)",
            group_id_bytes, user_id
        )
        
        if not is_member:
            raise HTTPException(403, "Not a group member")
        
        # Get all epoch secrets
        rows = await conn.fetch(
            "SELECT epoch FROM epoch_secrets WHERE group_id = $1 ORDER BY epoch",
            group_id_bytes
        )

        
        return {
            "group_id": group_id,
            "epochs": [row["epoch"] for row in rows]
        }