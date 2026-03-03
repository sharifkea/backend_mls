# delivery_service.py
from fastapi import FastAPI, HTTPException, Body, Response, Query
from fastapi.responses import JSONResponse
from typing import Optional, List
from uuid import uuid4, UUID
from datetime import datetime, timedelta
import uvicorn
#import database_del as db_del
from database_del import db_del

app = FastAPI(title="Delivery Service", description="MLS Key Package and Message Delivery Service")

@app.on_event("startup")
async def startup():
    await db_del.connect()

@app.on_event("shutdown")
async def shutdown():
    await db_del.close()

@app.post("/user/{username}")
async def upload_keypackage(username: str, key_package: bytes = Body(...)):
    """
    Store a user's key package
    The client sends their serialized KeyPackage
    """
    try:
        async with db_del.connection() as conn:
            # Check if user exists, create if not
            user = await conn.fetchval(
                "SELECT user_id FROM users WHERE username = $1",
                username
            )
            
            if not user:
                # Create new user
                user_id = await conn.fetchval(
                    """
                    INSERT INTO users (username, created_at)
                    VALUES ($1, NOW())
                    RETURNING user_id
                    """,
                    username
                )
            else:
                # Deactivate old key packages
                await conn.execute(
                    """
                    UPDATE key_packages 
                    SET is_active = FALSE 
                    WHERE username = $1
                    """,
                    username
                )
            
            # Store new key package
            key_package_id = await conn.fetchval(
                """
                INSERT INTO key_packages (key_package_id, username, key_package, 
                                        created_at, expires_at, is_active)
                VALUES (gen_random_uuid(), $1, $2, NOW(), NOW() + INTERVAL '30 days', TRUE)
                RETURNING key_package_id
                """,
                username, key_package
            )
            
            return {
                "status": "stored", 
                "username": username,
                "key_package_id": str(key_package_id)
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to store key package: {str(e)}")

@app.get("/user/{username}")
async def get_keypackage(username: str):
    """
    Retrieve a user's latest active key package
    Returns raw binary KeyPackage data
    """
    try:
        async with db_del.connection() as conn:
            key_package = await conn.fetchrow(
                """
                SELECT key_package, created_at, expires_at
                FROM key_packages
                WHERE username = $1 AND is_active = TRUE AND expires_at > NOW()
                ORDER BY created_at DESC
                LIMIT 1
                """,
                username
            )
            
            if not key_package:
                raise HTTPException(status_code=404, detail="No active key package found for user")
            
            return Response(
                content=key_package["key_package"],
                media_type="application/octet-stream",
                headers={
                    "X-Created-At": key_package["created_at"].isoformat(),
                    "X-Expires-At": key_package["expires_at"].isoformat()
                }
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve key package: {str(e)}")

@app.post("/message")
async def post_message(message: bytes = Body(...)):
    """
    Post a group message (commit, proposal, welcome, etc.)
    """
    try:
        message_id = str(uuid4())
        
        async with db_del.connection() as conn:
            # Try to extract some metadata for better storage
            # In a real implementation, you'd parse the MLS message
            await conn.execute(
                """
                INSERT INTO group_messages (message_id, message_content, created_at)
                VALUES ($1, $2, NOW())
                """,
                message_id, message
            )
            
            return {
                "status": "posted", 
                "message_id": message_id,
                "timestamp": datetime.now().isoformat()
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to post message: {str(e)}")

@app.post("/message/with-metadata")
async def post_message_with_metadata(
    message: bytes = Body(...),
    message_type: str = Body(...),
    sender: str = Body(...),
    group_id: str = Body(...),
    epoch: int = Body(...)
):
    """
    Post a group message with additional metadata
    """
    try:
        message_id = str(uuid4())
        
        async with db_del.connection() as conn:
            await conn.execute(
                """
                INSERT INTO group_messages (message_id, message_type, message_content, 
                                          sender, group_id, epoch, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, NOW())
                """,
                message_id, message_type, message, sender, group_id, epoch
            )
            
            return {
                "status": "posted", 
                "message_id": message_id,
                "timestamp": datetime.now().isoformat()
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to post message: {str(e)}")

@app.get("/messages")
async def get_messages(
    since: Optional[str] = Query(None, description="ISO format timestamp"),
    group_id: Optional[str] = Query(None, description="Filter by group ID"),
    limit: int = Query(100, description="Maximum number of messages to return")
):
    """
    Get all messages, optionally filtered by time and group
    """
    try:
        async with db_del.connection() as conn:
            query = "SELECT * FROM group_messages WHERE 1=1"
            params = []
            param_idx = 1
            
            if since:
                try:
                    since_dt = datetime.fromisoformat(since)
                    query += f" AND created_at > ${param_idx}"
                    params.append(since_dt)
                    param_idx += 1
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid since timestamp format")
            
            if group_id:
                query += f" AND group_id = ${param_idx}"
                params.append(group_id)
                param_idx += 1
            
            query += f" ORDER BY created_at DESC LIMIT ${param_idx}"
            params.append(limit)
            
            rows = await conn.fetch(query, *params)
            
            return {
                "messages": [
                    {
                        "message_id": str(row["message_id"]),
                        "message_type": row["message_type"],
                        "message": row["message_content"].hex(),
                        "sender": row["sender"],
                        "group_id": row["group_id"],
                        "epoch": row["epoch"],
                        "created_at": row["created_at"].isoformat()
                    }
                    for row in rows
                ],
                "count": len(rows)
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve messages: {str(e)}")

@app.get("/messages/{group_id}/since/{epoch}")
async def get_messages_since_epoch(group_id: str, epoch: int):
    """
    Get all messages for a group since a specific epoch
    """
    try:
        async with db_del.connection() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM group_messages
                WHERE group_id = $1 AND epoch > $2
                ORDER BY epoch ASC, created_at ASC
                """,
                group_id, epoch
            )
            
            return {
                "messages": [
                    {
                        "message_id": str(row["message_id"]),
                        "message_type": row["message_type"],
                        "message": row["message_content"].hex(),
                        "sender": row["sender"],
                        "epoch": row["epoch"],
                        "created_at": row["created_at"].isoformat()
                    }
                    for row in rows
                ],
                "count": len(rows)
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve messages: {str(e)}")

@app.delete("/user/{username}")
async def delete_user(username: str):
    """
    Delete a user and all their key packages
    """
    try:
        async with db_del.connection() as conn:
            # Delete key packages first
            await conn.execute(
                "DELETE FROM key_packages WHERE username = $1",
                username
            )
            
            # Delete user
            result = await conn.execute(
                "DELETE FROM users WHERE username = $1",
                username
            )
            
            if result == "DELETE 0":
                raise HTTPException(status_code=404, detail="User not found")
            
            return {"status": "deleted", "username": username}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete user: {str(e)}")

@app.get("/health")
async def health_check():
    """
    Health check endpoint
    """
    try:
        async with db_del.connection() as conn:
            await conn.fetchval("SELECT 1")
            return {
                "status": "healthy",
                "database": "connected",
                "timestamp": datetime.now().isoformat()
            }
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "database": "disconnected",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
        )

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=1338)